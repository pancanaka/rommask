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

import fr.gouv.ssi.rommask.jcaparser.JCAClassMethodSignature;
import fr.gouv.ssi.rommask.jcaparser.JCAType;

/**
 * Description of a JCA method defined as native
 *
 * @author Guillaume Bouffard
 */
public class JCANativeMethod {

    /**
     * Native method package name
     */
    private String packageName;

    /**
     * Native method signature
     */
    private JCAClassMethodSignature signature;

    /**
     * Class constructor
     *
     * @param packageName
     * @param signature   method signature
     */
    public JCANativeMethod(String packageName, JCAClassMethodSignature signature) {
        this.packageName = packageName;
        this.signature = signature;
    }

    /**
     * Get method signature
     *
     * @return method signature
     */
    public JCAClassMethodSignature getSignature() {
        return signature;
    }

    /**
     * Get package name
     *
     * @return package name
     */
    public String getPackageName() {
        return packageName;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append(this.signature.getReturnType().prettyToString() + " "
                + this.packageName + "." + this.signature.getName().replace("/", "."));

        out.append("(");
        for (int index = 0; index < this.signature.getParameters().size(); index++) {
            JCAType param = this.signature.getParameters().get(index);
            out.append(param.prettyToString());

            if (index < (this.signature.getParameters().size() - 1)) {
                out.append(", ");
            }
        }
        out.append(")");

        return out.toString();
    }
}
