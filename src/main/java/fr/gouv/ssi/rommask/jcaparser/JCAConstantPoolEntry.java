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
 * JCA file Constant Pool entry
 *
 * @author Guillaume Bouffard
 */
public class JCAConstantPoolEntry {
    private ArrayList<JCADescriptor> descriptors;

    /**
     * Default constructor
     */
    public JCAConstantPoolEntry() {
        this.descriptors = new ArrayList<>();
    }

    /**
     * Get constant pool entry's associated descriptors
     *
     * @return get associated descriptors
     */
    public ArrayList<JCADescriptor> getDescriptors() {
        return descriptors;
    }

    /**
     * Set constant pool entry's associated descriptors
     *
     * @param descriptors new associated descriptors
     */
    public void setDescriptors(ArrayList<JCADescriptor> descriptors) {
        this.descriptors = descriptors;
    }

    /**
     * Add a descriptor to the constant pool entry
     *
     * @param descriptor the descriptor to add
     */
    public void addDescriptor(JCADescriptor descriptor) {
        this.descriptors.add(descriptor);
    }
}
