package fr.gouv.ssi.rommask.jcaparser.jcaconverter;

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

import fr.gouv.ssi.rommask.jcaparser.*;
import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.ClassExportsInfo;
import fr.xlim.ssd.capmanipulator.library.ComponentEnum;
import fr.xlim.ssd.capmanipulator.library.ExportComponent;

import java.util.ArrayList;

/**
 * Translate Export component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ExportComponentFromJCA extends ExportComponent implements ComponentUtils, Cloneable {

    /**
     * Input JCA file used to compute the CAP file export component
     */
    JCAFile jca;

    /**
     * Class constructor
     *
     * @param cap JCA file used to generate Export component
     * @param jca JCA file used to generate Export component
     */
    ExportComponentFromJCA(CapFile cap, JCAFile jca) {
        this.setTag((byte) ComponentEnum.EXPORT_COMPONENT.getValue());

        this.jca = jca;

        ArrayList<ClassExportsInfo> classExports = new ArrayList<>();
        short classOffset = 0;

        MethodComponentFromJCA methodComponent = (MethodComponentFromJCA) cap.getMethodComponent();
        StaticFieldComponentFromJCA staticFieldComponent = (StaticFieldComponentFromJCA) cap.getStaticFieldComponent();

        boolean isAppletPackage = (jca.getApplets() != null);

        for (JCAObject object : jca.getClaz().getClasses()) {
            ClassExportsInfoFromJCA classExport = new ClassExportsInfoFromJCA();
            ArrayList<Short> static_field_offsets = new ArrayList<>();
            ArrayList<Short> static_method_offsets = new ArrayList<>();
            ArrayList<JCAClassField> static_fields = new ArrayList<>();

            classExport.setClassOffset(classOffset);
            classOffset += object.classSize();

            if (isAppletPackage) { // Applet Package

                /**
                 * If this CAP file includes an Applet Component (§6.5) (called an applet package) the
                 * Export Component includes entries only for all public interfaces that are shareable.
                 * An interface is sharable if and only if it is the javacard.framework.Shareable
                 * interface or implements (directly or indirectly) that interface.
                 */

                if (!(object instanceof JCAInterface)) {
                    continue;
                }

                JCAInterface jcaInterface = (JCAInterface) object;

                if (!jcaInterface.isShareable()) {
                    continue;
                }

                for (JCAClassField field : object.getFields()) {
                    if (field.isFinal()) {
                        continue;
                    }

                    short offset = staticFieldComponent.getStaticFieldImage().row(field.getName()).keySet().iterator().next();
                    static_field_offsets.add(offset);
                    static_fields.add(field);
                }

                for (JCAClassMethod method : object.getMethods()) {

                    if (!method.isStatic()) {
                        continue;
                    }

                    String fullMethodName = method.getMethodSignature().getFullName();
                    short staticMethodOffset = methodComponent.getMethodsWithOffsets().get(fullMethodName);
                    static_method_offsets.add(staticMethodOffset);
                }

            } else { // Library package

                /*
                 * If this CAP file does not include an Applet Component (§6.5) (called a library
                 * package), the Export Component contains an entry for each public class and
                 * public interface defined in this package. Furthermore, for each public class there is
                 * an entry for each public or protected static field defined in that class, for each
                 * public or protected static method defined in that class, and for each public or
                 * protected constructor defined in that class. Final static fields of primitive types
                 * (compile-time constants) are not included.
                 */

                // Only public classes/interfaces are listed in export component
                if (object.getAccessor() != JCAAccessor.PUBLIC) {
                    continue;
                }


                for (JCAClassField field : object.getFields()) {
                    switch (field.getAccessor()) {
                        case PUBLIC:
                        case PROTECTED:
                            if (field.isStatic() && !field.isFinal()) {
                                short offset = staticFieldComponent.getStaticFieldImage().row(field.getName()).keySet().iterator().next();
                                static_field_offsets.add(offset);
                                static_fields.add(field);
                            }
                            break;
                    }
                }

                for (JCAClassMethod method : object.getMethods()) {
                    switch (method.getAccessor()) {
                        case PUBLIC:
                        case PROTECTED:
                            if (method.isStatic() || method.getMethodSignature().getName().contains("<init>")) {
                                String fullMethodName = method.getMethodSignature().getFullName();
                                short staticMethodOffset = methodComponent.getMethodsWithOffsets().get(fullMethodName);
                                static_method_offsets.add(staticMethodOffset);
                            }
                            break;
                    }
                }
            }


            classExport.setStaticFieldCount((byte) static_field_offsets.size());
            classExport.setStaticMethodCount((byte) static_method_offsets.size());
            classExport.setStaticFieldOffsets(static_field_offsets);
            classExport.setStaticMethodOffsets(static_method_offsets);
            classExport.setStaticFields(static_fields);

            classExports.add(classExport);
        }

        this.setClassExports(classExports);
        this.setClassCount((byte) this.getClassExports().size());
        this.setSize(this.computeComponentSize());
    }

    /**
     * Empty constructor
     */
    private ExportComponentFromJCA() {
    }

    @Override
    public short computeComponentSize() {
        short class_exports_size = 0;

        for (ClassExportsInfo classExports : this.getClassExports()) {
            class_exports_size += ((ComponentUtils) classExports).computeComponentSize();
        }

        if (class_exports_size == 0) {
            return 0;
        } else {
            return (short) (Byte.BYTES // class_count
                    + class_exports_size);
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ExportComponentFromJCA out = new ExportComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());
        out.setClassCount(this.getClassCount());

        ArrayList<ClassExportsInfo> exportsInfos = new ArrayList<>();
        for (ClassExportsInfo classExportsInfo : this.getClassExports()) {
            exportsInfos.add((ClassExportsInfo) classExportsInfo.clone());
        }
        out.setClassExports(exportsInfos);

        out.jca = this.jca;

        return out;
    }
}
