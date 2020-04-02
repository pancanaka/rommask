package fr.gouv.ssi.rommask.jcaparser.bytecodes;

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

import fr.gouv.ssi.rommask.jcaparser.Bytecode;
import fr.gouv.ssi.rommask.jcaparser.Instruction;

import java.security.InvalidParameterException;
import java.util.ArrayList;

/**
 * instanceof instructions class
 *
 * @author Guillaume Bouffard
 */
public class INSTANCEOF extends Instruction {

    /**
     * Class constructor
     *
     * @param parameters instruction parameters list
     */
    public INSTANCEOF(ArrayList<String> parameters) {
        super(Bytecode.INSTANCEOF, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {
        ArrayList<Byte> params = new ArrayList<>();


        /**
         * values allow:
         *    instanceof 10 0;
         *    instanceof 11 0;
         *    instanceof 12 0;
         *    instanceof 13 0;
         *    instanceof 14 0;
         */

        if (parameters.size() != 2) {
            throw new InvalidParameterException
                    (this.getOpcode() + " has invalid parameters size.");
        }

        byte aType = (byte) Integer.parseInt(parameters.get(0));
        short index = (short) Integer.parseInt(parameters.get(1));

        if ((aType < 10) && (aType > 14)) {
            throw new InvalidParameterException
                    ("invalid " + Bytecode.INSTANCEOF + " type parameter");
        }

        params.add(aType);
        params.add((byte) (index >> 8));
        params.add((byte) index);

        return params;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();
        ArrayList<Byte> params = this.getParameters();

        out.append(super.toString() + " ");

        switch (this.getParameters().get(0)) {
            case 10:
                out.append("boolean[]");
                break;
            case 11:
                out.append("byte[]");
                break;
            case 12:
                out.append("short[]");
                break;
            case 13:
                out.append("int[]");
                break;
            default:
                throw new InvalidParameterException(this.getOpcode() + ": invalid parameter value");
        }

        short value = (short) (((params.get(1) & 0x00FF) << 8) | (params.get(2) & 0x00FF));
        out.append(value);

        return out.toString();
    }

}
