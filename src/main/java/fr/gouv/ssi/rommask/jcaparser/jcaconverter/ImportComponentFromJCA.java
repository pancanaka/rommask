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

import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.gouv.ssi.rommask.jcaparser.JCAImportComponent;
import fr.gouv.ssi.rommask.jcaparser.JCAPackage;
import fr.xlim.ssd.capmanipulator.library.ComponentEnum;
import fr.xlim.ssd.capmanipulator.library.ImportComponent;
import fr.xlim.ssd.capmanipulator.library.PackageInfo;

import java.util.ArrayList;

/**
 * Translate Import component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ImportComponentFromJCA extends ImportComponent implements ComponentUtils, Cloneable {

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate import component
     */
    public ImportComponentFromJCA(JCAFile jca) {
        this.setTag((byte) ComponentEnum.IMPORT_COMPONENT.getValue());

        JCAImportComponent importedPackages = jca.getImportedPackages();

        if (importedPackages == null) {
            this.setCount((byte) 0);
            this.setPackages(new ArrayList<>());
            this.setSize((byte) this.computeComponentSize());

            return;
        }

        ArrayList<PackageInfo> packageInfos = new ArrayList<>();

        for (JCAPackage pckg : importedPackages.getEntries()) {
            PackageInfoFromJCA packageInfo = new PackageInfoFromJCA
                    (pckg.getMajorVersion(), pckg.getMinorVersion(), pckg.getAID());
            packageInfos.add(packageInfo);
        }

        // Trim the arraylist
        packageInfos.trimToSize();

        this.setCount((byte) packageInfos.size());
        this.setPackages(packageInfos);

        this.setSize(this.computeComponentSize());
    }

    /**
     * Empty constructor
     */
    private ImportComponentFromJCA() {
    }

    @Override
    public short computeComponentSize() {
        short size = Byte.BYTES; // count

        for (PackageInfo packageInfo : this.getPackages()) {
            size += ((ComponentUtils) packageInfo).computeComponentSize();
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ImportComponentFromJCA out = new ImportComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        out.setCount(this.getCount());

        ArrayList<PackageInfo> packages = new ArrayList<>();
        for (PackageInfo p : this.getPackages()) {
            packages.add((PackageInfo) p.clone());
        }
        out.setPackages(packages);

        return out;
    }
}
