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
 * checkcast instructions class
 *
 * @author Guillaume Bouffard
 */
public class CHECKCAST extends Instruction {
    /**
     * Default class constructor
     *
     * @param parameters instruction parameter
     */
    public CHECKCAST(ArrayList<String> parameters) {
        super(Bytecode.CHECKCAST, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {

        ArrayList<Byte> params = new ArrayList<>();

        /**
         * Allow values:
         *    checkcast 10 0;
         *    checkcast 11 0;
         *    checkcast 12 0;
         *    checkcast 13 0;
         *    checkcast 14 0;
         */

        if (parameters.size() != 2) {
            throw new InvalidParameterException
                    (this.getOpcode() + " has invalid parameters size.");
        }

        byte aType = (byte) Integer.parseInt(parameters.get(0));
        short index = (short) Integer.parseInt(parameters.get(1));

        params.add(aType);
        params.add((byte) ((index & 0xFF00) >> 8));
        params.add((byte) ((index & 0x00FF)));

        return params;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append(super.toString() + " ");

        ArrayList<Byte> params = this.getParameters();

        switch (params.get(0)) {
            case 10:
                out.append("T_BOOLEAN ");
                break;
            case 11:
                out.append("T_BYTE ");
                break;
            case 12:
                out.append("T_SHORT ");
                break;
            case 13:
                out.append("T_INT ");
                break;
            case 14:
                out.append("T_REFERENCE ");
                break;
            default:
                throw new InvalidParameterException(this.getOpcode() + ": invalid parameter value");
        }

        short index = (short) ((params.get(1) << 8) | (params.get(0) & 0x00FF));

        out.append(index & 0x00FFFF);

        return out.toString();
    }
}
