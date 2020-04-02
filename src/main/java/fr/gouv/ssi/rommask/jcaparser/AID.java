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
 * AID class to compute AID from JCA file to CAP file
 *
 * @author Guillaume Bouffard
 */
public class AID {

    /**
     * Constant hexadecimal array used to convert hex values to string
     */
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    /**
     * AID value
     */
    private byte[] aid;

    /**
     * Default constructor
     *
     * @param aid AID
     */
    public AID(byte[] aid) {
        this.aid = aid;
    }

    /**
     * AID getter
     *
     * @return aid current aid
     */
    public byte[] getAID() {
        return aid;
    }

    /**
     * AID setter
     *
     * @param aid new aid
     */
    public void setAID(byte[] aid) {
        this.aid = aid;
    }

    @Override
    public String toString() {
        char[] hexChars = new char[this.aid.length * 2];
        for (int j = 0; j < this.aid.length; j++) {
            int v = this.aid[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
