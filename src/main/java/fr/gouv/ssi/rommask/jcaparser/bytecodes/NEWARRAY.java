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
 * newarray instructions class
 *
 * @author Guillaume Bouffard
 */
public class NEWARRAY extends Instruction {

    /**
     * Default class constructor
     *
     * @param parameters instruction parameter
     */
    public NEWARRAY(ArrayList<String> parameters) {
        super(Bytecode.NEWARRAY, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {
        ArrayList<Byte> params = new ArrayList<>();
        byte aType;

        /**
         * Allow values:
         *    newarray 10;
         *    newarray 11;
         *    newarray 12;
         *    newarray 13;
         *    newarray boolean[];  // array types may be declared numerically or
         *    newarray byte[];     // symbolically.
         *    newarray short[];
         *    newarray int[];
         */

        if (parameters.size() != 1) {
            throw new InvalidParameterException
                    (this.getOpcode() + " has invalid parameters size.");
        }

        switch (parameters.get(0)) {
            case "10":
            case "11":
            case "12":
            case "13":
                aType = (byte) Integer.parseInt(parameters.get(0));
                break;
            case "boolean[]":
                aType = 10;
                break;
            case "byte[]":
                aType = 11;
                break;
            case "short[]":
                aType = 12;
                break;
            case "int[]":
                aType = 13;
                break;
            default:
                throw new InvalidParameterException();
        }

        params.add(aType);

        return params;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

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

        return out.toString();
    }
}
