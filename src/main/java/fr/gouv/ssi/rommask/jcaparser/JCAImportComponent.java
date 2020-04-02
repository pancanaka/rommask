package fr.gouv.ssi.rommask.jcaparser;

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

import java.util.ArrayList;

/**
 * JCA import component definition
 *
 * @author Guillaume Bouffard
 */
public class JCAImportComponent {

    /**
     * List of JCA Import component entries
     */
    private ArrayList<JCAPackage> entries;

    /**
     * Default constructor
     */
    JCAImportComponent(ArrayList<JCAPackage> entries) {
        this.entries = entries;
    }

    /**
     * Get imported packages entries
     *
     * @return imported packages entries
     */
    public ArrayList<JCAPackage> getEntries() {
        return entries;
    }

    /**
     * Set imported packages entries
     *
     * @param entries imported packages entries
     */
    public void setEntries(ArrayList<JCAPackage> entries) {
        this.entries = entries;
    }

    /**
     * Add a imported packages entry
     *
     * @param entry a imported packages entry to add
     */
    void addEntry(JCAPackage entry) {
        this.entries.add(entry);
    }
}
