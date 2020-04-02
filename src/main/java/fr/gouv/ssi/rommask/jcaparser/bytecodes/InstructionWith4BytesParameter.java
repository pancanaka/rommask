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

import java.security.InvalidParameterException;
import java.util.ArrayList;

/**
 * Meta class for instruction with 4-byte parameter
 *
 * @author Guillaume Bouffard
 */
public class InstructionWith4BytesParameter extends InstructionWithBytesParameter {

    /**
     * Class constructor
     *
     * @param opcode     opcode value
     * @param parameters instruction parameters
     */
    public InstructionWith4BytesParameter(Bytecode opcode, ArrayList<String> parameters) {
        super(opcode, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {

        ArrayList<Byte> params = new ArrayList<>();

        int value = Integer.parseInt(parameters.get(0));

        params.add((byte) (value & 0xFF000000));
        params.add((byte) (value & 0x00FF0000));
        params.add((byte) (value & 0x0000FF00));
        params.add((byte) (value & 0x000000FF));

        return params;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        int value = ((this.getParameters().get(0) & 0x00FF) << 24)
                | ((this.getParameters().get(1) & 0x00FF) << 16)
                | ((this.getParameters().get(2) & 0x00FF) << 8)
                | (this.getParameters().get(3) & 0x00FF);

        out.append(super.toString() + " " + value);

        return out.toString();
    }

}
