#!/usr/bin/python3
#
# The MIT License (MIT)
#
# Copyright (c) 2013 Andrian Nord
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import logging
import os
import sys
from optparse import OptionParser

import ljd.rawdump.parser
import ljd.rawdump.code
import ljd.pseudoasm.writer
import ljd.pseudoasm.instructions
import ljd.ast.builder
import ljd.ast.slotworks
import ljd.ast.validator
import ljd.ast.locals
import ljd.ast.unwarper
import ljd.ast.mutator
import ljd.lua.writer

import ljd.ast.nodes as nodes


class MakeFileHandler(logging.FileHandler):
    def __init__(self, filename, *args, **kwargs):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        logging.FileHandler.__init__(self, filename, *args, **kwargs)


def set_luajit_version(bc_version):
    # If we're already on this version, skip resetting everything
    if ljd.CURRENT_VERSION == bc_version:
        return

    ljd.CURRENT_VERSION = bc_version
    # Now we know the LuaJIT version, initialise the opcodes
    if bc_version == 2.0:
        from ljd.rawdump.luajit.v2_0.luajit_opcode import _OPCODES as opcodes
    else:
        raise Exception("Unknown LuaJIT opcode module name for version " + str(bc_version))

    ljd.rawdump.code.init(opcodes)
    ljd.ast.builder.init()
    ljd.pseudoasm.instructions.init()


class Main:
    def __init__(self):
        # Parser arguments
        parser = OptionParser()

        # Single file input target. Not to be used with -r
        parser.add_option("-f", "--file",
                          type="string", dest="file_name", default="",
                          help="input file name", metavar="FILE")

        # Directory in which to recurse and process all files. Not to be used with -f
        parser.add_option("-r", "--recursive",
                          type="string", dest="folder_name", default="",
                          help="recursively decompile lua files", metavar="FOLDER")

        # Single file output destination. Not to be used with -r
        parser.add_option("-o", "--output",
                          type="string", dest="output", default="",
                          help="output file for writing")

        # LEGACY OPTION. Directory to output processed files during recursion. Not to be used with -f
        parser.add_option("-d", "--dir_out",
                          type="string", dest="folder_output", default="",
                          help="LEGACY OPTION. directory to output decompiled lua scripts", metavar="FOLDER")

        (self.options, args) = parser.parse_args()

        # Allow the input argument to be either a folder or a file.
        if len(args) == 1:
            if self.options.file_name or self.options.folder_name:
                parser.error("Conflicting file arguments.")
                sys.exit(1)

            if os.path.isdir(args[0]):
                self.options.folder_name = args[0]
            else:
                self.options.file_name = args[0]
        elif len(args) > 1:
            parser.error("Too many arguments.")
            sys.exit(1)

        # Verify arguments
        if self.options.folder_name:
            pass
        elif not self.options.file_name:
            parser.error("Options -f or -r are required.")
            sys.exit(1)

        # Determine output folder/file
        if self.options.folder_output:
            if not self.options.output:
                self.options.output = self.options.folder_output
            self.options.folder_output = None

        if self.options.output:
            if self.options.folder_name:
                if os.path.isfile(self.options.output):
                    parser.error("Output folder is a file.")
                    sys.exit(0)

    def main(self):
        # Recursive batch processing
        if self.options.folder_name:
            self.options.folder_name = os.path.sep.join(os.path.normpath(self.options.folder_name).split('\\'))
            for path, _, file_names in os.walk(self.options.folder_name):
                for file in file_names:
                    # Skip files we're not interested in based on the extension
                    if not file.endswith(".lo"):
                        continue

                    full_path = os.path.join(path, file)

                    # Process current file
                    try:
                        self.process_file(file, full_path)
                    except (KeyboardInterrupt, SystemExit):
                        print("Interrupted")
                        sys.stdout.flush()
                        return 0
                    except Exception as exc:
                        print("\n--; Exception in {0}".format(full_path))
                        print(exc)
            return 0

        # Single file processing
        ast = self.decompile(self.options.file_name)

        if not ast:
            return 1

        if self.options.output:
            output_file = self.options.output
            if os.path.isdir(output_file):
                output_file = os.path.join(
                    output_file, os.path.splitext(os.path.basename(self.options.file_name))[0], ".lua"
                )
            print("output: {0}".format(output_file))
            self.write_file(ast, output_file, False)
        else:
            ljd.lua.writer.write(sys.stdout, ast, False)

        return 0

    def process_file(self, file, full_path):
        try:
            ast = self.decompile(full_path)

            if not self.options.output:
                print("\n--; Decompile of {0}".format(full_path))
                ljd.lua.writer.write(sys.stdout, ast)
                self.lock.release()
                return 0

            new_path = os.path.join(self.options.output, os.path.relpath(full_path, self.options.folder_name))
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            if file.endswith('.lo'):
                new_path = new_path[:-1]+"ua"
            print("output: {0}".format(new_path))
            self.write_file(ast, new_path)
            return 0
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise

    def write_file(self, ast, file_name, **kwargs):
        with open(file_name, "w", encoding="utf8") as out_file:
            return ljd.lua.writer.write(out_file, ast, **kwargs)

    def decompile(self, file_in):
        def on_parse_header(preheader):
            # Identify the version of LuaJIT used to compile the file
            bc_version = None
            if preheader.version == 1:
                bc_version = 2.0
            elif preheader.version == 2:
                bc_version = 2.1
            else:
                raise Exception("Unsupported bytecode version: " + str(bc_version))

            set_luajit_version(bc_version)

        header, prototype = ljd.rawdump.parser.parse(file_in, on_parse_header)

        if not prototype:
            return 1

        ast = ljd.ast.builder.build(header, prototype)

        assert ast is not None

        ljd.ast.validator.validate(ast, warped=True)

        ljd.ast.mutator.pre_pass(ast)

        ljd.ast.validator.validate(ast, warped=True)

        ljd.ast.locals.mark_locals(ast)

        try:
            ljd.ast.slotworks.eliminate_temporary(ast, identify_slots=True)
        except AssertionError:
                raise

        ljd.ast.unwarper.unwarp(ast, False)

        if True:
            ljd.ast.locals.mark_local_definitions(ast)

            # ljd.ast.validator.validate(ast, warped=False)

            ljd.ast.mutator.primary_pass(ast)

            try:
                ljd.ast.validator.validate(ast, warped=False)
            except AssertionError:
                    raise

            if True:
                # Mark remaining (unused) locals in empty loops, before blocks and at the end of functions
                ljd.ast.locals.mark_locals(ast, alt_mode=True)
                ljd.ast.locals.mark_local_definitions(ast)

                # Extra (unsafe) slot elimination pass (iff debug info is available) to deal with compiler issues
                for ass in ast.statements.contents:
                    if not isinstance(ass, nodes.Assignment):
                        continue

                    for node in ass.expressions.contents:
                        if not getattr(node, "_debuginfo", False) or not node._debuginfo.variable_info:
                            continue

                        contents = None
                        if isinstance(node, nodes.FunctionDefinition):
                            contents = [node.statements.contents]
                        elif isinstance(node, nodes.TableConstructor):
                            contents = [node.array.contents, node.records.contents]
                        else:
                            continue

                        # Check for any remaining slots
                        try:
                            for content_list in contents:
                                for subnode in content_list:
                                    if isinstance(subnode, nodes.Assignment):
                                        for dst in subnode.destinations.contents:
                                            if isinstance(dst, nodes.Identifier) and dst.type == dst.T_SLOT:
                                                raise StopIteration
                        except StopIteration:
                            ljd.ast.slotworks.eliminate_temporary(node, unwarped=True, safe_mode=False)

                            # Manual cleanup
                            for content_list in contents:
                                j = len(content_list) - 1
                                for i, subnode in enumerate(reversed(content_list)):
                                    if getattr(subnode, "_invalidated", False):
                                        del content_list[j - i]

        return ast


if __name__ == "__main__":
    main_obj = Main()
    retval = main_obj.main()
    sys.exit(retval)
