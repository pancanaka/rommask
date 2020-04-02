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
 * itableswitch instructions class
 *
 * @author Guillaume Bouffard
 */
public class ITABLESWITCH extends InstructionSwitch {

    /**
     * Default label value
     */
    private short defaultLabel;
    /**
     * low and high label values
     */
    private int low, high;
    /**
     * List of label
     */
    private ArrayList<Short> labels;

    /**
     * Default class constructor
     *
     * @param parameters instruction parameter
     */
    public ITABLESWITCH(ArrayList<String> parameters) {
        super(Bytecode.ITABLESWITCH, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {

        ArrayList<Byte> params = new ArrayList<>();

        /**
         * value allows:
         *   itableswitch L30 1 6 L26 L27 L30 L30 L28 L29;
         */

        this.labels = new ArrayList<>();

        defaultLabel = (short) Integer.parseInt(parameters.get(0).substring(1));
        low = Integer.parseInt(parameters.get(1));
        high = Integer.parseInt(parameters.get(2));

        params.add((byte) ((defaultLabel >> 8) & 0x00FF));
        params.add((byte) defaultLabel);

        params.add((byte) ((low >> 24) & 0x00FF));
        params.add((byte) ((low >> 16) & 0x00FF));
        params.add((byte) ((low >> 8) & 0x00FF));
        params.add((byte) (low & 0x00FF));

        params.add((byte) ((high >> 24) & 0x00FF));
        params.add((byte) ((high >> 16) & 0x00FF));
        params.add((byte) ((high >> 8) & 0x00FF));
        params.add((byte) (high & 0x00FF));

        if (parameters.size() != ((high - low) + 3 + 1)) {
            throw new InvalidParameterException
                    (this.getOpcode() + " has invalid parameters size.");
        }

        for (int foo = 0; foo <= (high - low); foo++) {
            short offset = (short) Integer.parseInt(parameters.get(foo + 3).substring(1));
            this.labels.add(offset);

            params.add((byte) 0); // fill by zero and update later
            params.add((byte) 0);
        }

        return params;
    }

    @Override
    public void updateLabels(ArrayList<Short> methodsLabels, ArrayList<Instruction> methodBytecodes, short methodOffset) {
        ArrayList<Byte> params = this.getParameters();

        // update defaultLabel value
        int labelValue = 0;
        for (short foo = 0; foo < methodsLabels.get(this.defaultLabel); foo++) {
            labelValue += methodBytecodes.get(foo).getInstructionSize();
        }

        labelValue = labelValue - methodOffset;
        params.set(0, (byte) (labelValue >> 8));
        params.set(1, (byte) (labelValue & 0x00FF));

        int index = Short.BYTES // defaultLabel
                + Integer.BYTES // low
                + Integer.BYTES // high
                ;

        for (Short label : this.labels) {
            labelValue = 0;

            for (short foo = 0; foo < methodsLabels.get(label); foo++) {
                labelValue += methodBytecodes.get(foo).getInstructionSize();
            }

            labelValue = labelValue - methodOffset;

            params.set(index, (byte) (labelValue >> 8));
            index++;
            params.set(index, (byte) (labelValue & 0x00FF));
            index++;
        }
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append(super.toString());

        // default label
        out.append(" L" + this.defaultLabel);
        out.append(" " + this.low);
        out.append(" " + this.high);

        for (Short label : this.labels) {
            out.append(" L" + label);
        }

        return out.toString();
    }

}
