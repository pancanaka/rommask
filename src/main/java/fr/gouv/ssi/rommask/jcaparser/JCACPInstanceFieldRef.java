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

/**
 * JCA file constant pool instance field reference
 *
 * @author Guillaume Bouffard
 */
public class JCACPInstanceFieldRef extends JCACPFieldRef {

    /**
     * Default constructor
     *
     * @param type instance field type
     * @param name instance field name
     */
    public JCACPInstanceFieldRef(JCAType type, String name) {
        super(type, name);
    }

    /**
     * Class constructor
     *
     * @param type         field type
     * @param packageToken package token
     * @param classToken   class token
     * @param fieldToken   field token
     */
    public JCACPInstanceFieldRef(JCAType type, byte packageToken, byte classToken, byte fieldToken) {
        super(type, packageToken, classToken, fieldToken);
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append("instanceFieldRef "
                + this.getType().prettyToString()
                + " " + this.getName());

        return out.toString();
    }
}
