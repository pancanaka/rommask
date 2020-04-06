package fr.gouv.ssi.rommask.jcaparser.mask;

/*-
 * #%L
 * Java Card RomMask Generator
 * %%
 * Copyright (C) 2020 National Cybersecurity Agency of France (ANSSI)
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import fr.gouv.ssi.rommask.jcaparser.JCAClassMethodSignature;
import fr.gouv.ssi.rommask.jcaparser.JCAType;
import fr.gouv.ssi.rommask.jcaparser.Type;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCANativeMethod;

import java.io.PrintWriter;
import java.util.ArrayList;

/**
 * Class to write native function header. This file must be link to the JCVM to have callback to the native area.
 *
 * @author Guillaume Bouffard
 */
public class JCNativeFunctions {

    /**
     * Starting package value for the JCVM starter
     */
    private final short startingPackageIndex;

    /**
     * Starting class value for the JCVM starter
     */
    private final short startingClassIndex;

    /**
     * Starting method value for the JCVM starter
     */
    private final short startingMethodIndex;

    /**
     * List of native method to implement
     */
    private ArrayList<JCANativeMethod> nativeMethods;

    /**
     * Class constructor
     *
     * @param nativeMethods        native methods to implement
     * @param startingPackageIndex Package index where the starting method is located
     * @param startingClassIndex   Class index where the starting method is located
     * @param startingMethodIndex  Starting method index
     */
    public JCNativeFunctions(ArrayList<JCANativeMethod> nativeMethods,
                             short startingPackageIndex, short startingClassIndex,
                             short startingMethodIndex) {
        this.nativeMethods = nativeMethods;

        this.startingPackageIndex = startingPackageIndex;
        this.startingClassIndex = startingClassIndex;
        this.startingMethodIndex = startingMethodIndex;
    }

    /**
     * Writing C-Header file with:
     * - The list of native method to implemnet
     * - Constant for the JCVM
     * - native call method
     *
     * @param out stream to write the C-header
     */
    public void writeCHeader(PrintWriter out) {

        out.write("/*\n");
        out.write(" * This file was automatically generated.\n");
        out.write(" *\n");
        out.write(" * description: definition callJCNativeMethod to execute native method from JCVM.\n");
        out.write("*/\n");

        out.write("#ifndef JC_JNI\n");
        out.write("#define JC_JNI\n\n");
        // Includes
        out.write("#include \"types.hpp\"\n");
        out.write("#include \"context.hpp\"\n");
        out.write("#include \"jc_types/jc_array.hpp\"\n");
        out.write("#include \"jc_types/jc_array_type.hpp\"\n");
        out.write("\n");

        out.write("/* STARTING METHOD PARAMETERS */\n");
        out.write("#define STARTING_JAVACARD_PACKAGE 0x" + String.format("%02X", this.startingPackageIndex) + "\n");
        out.write("#define STARTING_JAVACARD_CLASS   0x" + String.format("%02X", this.startingClassIndex) + "\n");
        // XXX: +1 because of class constructor
        out.write("#define STARTING_JAVACARD_METHOD  0x" + String.format("%02X", this.startingMethodIndex + 1) + "\n\n");

        // Writing namespace
        out.write("namespace jcvm {\n");

        out.write("/* METHOD SIGNATURES TO IMPLEMENT */\n");

        for (int index = 0; index < this.nativeMethods.size(); index++) {
            JCANativeMethod method = this.nativeMethods.get(index);
            JCAClassMethodSignature signature = method.getSignature();

            out.write("extern ");

            // Printing the ret type
            JCAType ret = signature.getReturnType();
            if (ret.isArray()) {
                out.write("std::shared_ptr<JC_Array> ");
            } else {
                switch (ret.getType()) {
                    case BYTE:
                        out.write("jbyte_t ");
                        break;
                    case BOOLEAN:
                        out.write("jbool_t ");
                        break;
                    case SHORT:
                        out.write("jshort_t ");
                        break;
                    case INT:
                        out.write("jint_t ");
                        break;
                    case REFERENCE:
                        out.write("jref_t ");
                        break;
                    default:
                        out.write("void ");
                        break;
                }
            }

            // Printing the method name
            out.write(method.getPackageName().replace("/", "_") + "_" + method.getSignature().getName().replace("/", "_"));

            // Printing the params type
            out.write("(");
            ArrayList<JCAType> params = signature.getParameters();
            for (int pindex = 0; pindex < params.size(); pindex++) {
                JCAType param = params.get(pindex);

                if (param.isArray()) {
                    out.write("std::shared_ptr<JC_Array>");
                } else {
                    switch (param.getType()) {
                        case BYTE:
                            out.write("jbyte_t");
                            break;
                        case BOOLEAN:
                            out.write("jbool_t");
                            break;
                        case SHORT:
                            out.write("jshort_t");
                            break;
                        case INT:
                            out.write("jint_t");
                            break;
                        case REFERENCE:
                            out.write("jref_t");
                            break;
                    }
                }

                if ((pindex + 1) < params.size()) {
                    out.write(", ");
                }
            }
            out.write(");\n");
        }

        out.write("\n");

        out.write("/* CONSTANTS */\n");
        // find the longest word
        int length = 0;
        ArrayList<String> names = new ArrayList<>();
        for (int index = 0; index < this.nativeMethods.size(); index++) {
            JCANativeMethod method = this.nativeMethods.get(index);
            String name = method.getPackageName().replace("/", "_") + "_" + method.getSignature().getName().replace("/", "_");

            // Adding parameters in the function name
            ArrayList<JCAType> params = method.getSignature().getParameters();

            if (params.size() > 0) {
                name += "_";

                for (JCAType param : params) {

                    if (param.isArray()) {
                        name += "_Array_";
                    }

                    switch (param.getType()) {
                        case INT:
                            name += "I";
                            break;
                        case BYTE:
                            name += "B";
                            break;
                        case VOID:
                            name += "V";
                            break;
                        case SHORT:
                            name += "S";
                            break;
                        case BOOLEAN:
                            name += "Z";
                            break;
                        case REFERENCE:
                            name += "Object";
                            break;
                        default:
                    }
                }
            }

            names.add(name);

            if (name.length() > length) {
                length = name.length();
            }
        }

        // Writing defines
        for (int index = 0; index < names.size(); index++) {
            String name = names.get(index);
            out.write("#define " + String.format("%-" + length + "s", name.toUpperCase()) + "  " + String.format("0x%04X", index));
            out.write("\n");
        }
        out.write("\n\n");

        out.write("void callJCNativeMethod(Context& context, jshort_t index) {\n");

        out.write("  Stack& stack = context.getStack();\n");
        out.write("  Heap& heap = context.getHeap();\n");

        // Writing switch case-statement
        out.write("  switch(index) {\n");
        for (int index = 0; index < this.nativeMethods.size(); index++) {
            JCANativeMethod method = this.nativeMethods.get(index);
            String name = method.getPackageName().replace("/", "_") + "_" + method.getSignature().getName().replace("/", "_");
            out.write("    case " + names.get(index).toUpperCase() + ": {\n");
            out.write("      // Calling the method " + method.getSignature().getReturnType() + " " + method.getPackageName() + "." + method.getSignature().getFullName().replace("/", ".") + "\n");

            ArrayList<JCAType> params = method.getSignature().getParameters();
            for (int pindex = params.size() - 1; pindex >= 0; pindex--) {
                JCAType param = params.get(pindex);

                out.write("      ");
                if (param.isArray()) {
                    out.write("jref_t ");
                } else {
                    switch (param.getType()) {
                        case BYTE:
                            out.write("jbyte_t ");
                            break;
                        case BOOLEAN:
                            out.write("jbool_t ");
                            break;
                        case SHORT:
                            out.write("jshort_t ");
                            break;
                        case INT:
                            out.write("jint_t ");
                            break;
                        case REFERENCE:
                            out.write("jref_t ");
                            break;
                    }
                }
                out.write("param_" + String.format("%02x", pindex) + " = ");

                if (param.isArray()) {
                    out.write("stack.pop_Reference();\n");
                    out.write("      auto array_" + String.format("%02x", pindex) +
                            "= heap.getArray(" + "param_" + String.format("%02x", pindex) + ");\n");
                    out.write("      if(array_" + String.format("%02x", pindex) + "->getType() != ");
                    switch (param.getType()) {
                        case BYTE:
                            out.write("JAVA_ARRAY_T_BYTE) {\n");
                            break;
                        case BOOLEAN:
                            out.write("JAVA_ARRAY_T_BOOLEAN) {\n");
                            break;
                        case SHORT:
                            out.write("JAVA_ARRAY_T_SHORT) {\n");
                            break;
                        case INT:
                            out.write("JAVA_ARRAY_T_INT) {\n");
                            break;
                        case REFERENCE:
                            out.write("JAVA_ARRAY_T_REFERENCE) {\n");
                            break;
                    }
                    // TODO: PANIC !!!
                    out.write("        // TODO: PANIC !!!!\n");
                    out.write("      }\n");
                } else {
                    switch (param.getType()) {
                        case BYTE:
                            out.write("stack.pop_Byte();\n");
                            break;
                        case BOOLEAN:
                            out.write("byte2bool(stack.pop_Byte());\n");
                            break;
                        case SHORT:
                            out.write("stack.pop_Short();\n");
                            break;
                        case INT:
                            out.write("stack.pop_Int();\n");
                            break;
                        case REFERENCE:
                            out.write("stack.pop_Reference();\n");
                            break;
                    }
                }
            }

            out.write("\n");

            JCAType returnType = method.getSignature().getReturnType();
            if (returnType.getType() != Type.VOID) {
                out.write("      auto ret = " + name + "(");
            } else {
                out.write("      " + name + "(");
            }

            for (int pindex = 0; pindex < params.size(); pindex++) {
                if (params.get(pindex).isArray()) {
                    out.write("array_" + String.format("%02x", pindex));
                } else {
                    out.write("param_" + String.format("%02x", pindex));
                }

                if (pindex + 1 < params.size()) {
                    out.write(", ");
                }
            }
            out.write(");\n");

            if (returnType.isArray()) {
                out.write("    auto retRef = heap.addArray(*ret);\n");
                out.write("    stack.push_Reference(retRef);\n");
            } else {
                switch (returnType.getType()) {
                    case BYTE:
                        out.write("    stack.push_Byte(ret);\n");
                        break;
                    case BOOLEAN:
                        out.write("    stack.push_Byte(ret);\n");
                        break;
                    case SHORT:
                        out.write("    stack.push_Short(ret);\n");
                        break;
                    case INT:
                        out.write("    stack.push_Int(ret);\n");
                        break;
                    case REFERENCE:
                        out.write("    stack.push_Reference(ret);\n");
                        break;
                }
            }

            out.write("      break;\n");
            out.write("    }\n");
        }
        out.write("  }\n");

        out.write("}\n");

        out.write("} /* jcvm */\n");

        out.write("\n#endif /* JC_JNI */\n");
    }
}
