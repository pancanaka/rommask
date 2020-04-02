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
 * JCA file class component
 *
 * @author Guillaume Bouffard
 */
public class JCAClassComponent {

    /**
     * List of classed and interfaces defined in the JCA file
     */
    private ArrayList<JCAObject> classes;

    /**
     * Default constructor
     */
    JCAClassComponent() {
        this.classes = new ArrayList<>();
    }

    /**
     * Advanced class constructor
     *
     * @param classes List of classes and interfaces
     */
    public JCAClassComponent(ArrayList<JCAObject> classes) {
        this.classes = classes;
    }

    /**
     * Get list of classes and interfaces
     *
     * @return list of classes and interfaces
     */
    public ArrayList<JCAObject> getClasses() {
        return this.classes;
    }

    /**
     * Set list of classes and interfaces
     *
     * @param classes list of classes and interfaces
     */
    public void setClasses(ArrayList<JCAObject> classes) {
        this.classes = classes;
    }
}
