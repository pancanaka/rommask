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
import java.util.*;

/**
 * slookupswitch instructions class
 *
 * @author Guillaume Bouffard
 */
public class SLOOKUPSWITCH extends InstructionSwitch {

    /**
     * Default label value
     */
    private short defaultLabel;
    /**
     * Number of pair
     */
    private short npair;
    /**
     * List of pair values
     */
    private Map<Short, Short> pairs;

    /**
     * Class constructor
     *
     * @param parameters instruction parameters list
     */
    public SLOOKUPSWITCH(ArrayList<String> parameters) {
        super(Bytecode.SLOOKUPSWITCH, parameters);
    }

    @Override
    protected ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException {
        ArrayList<Byte> params = new ArrayList<>();

        /**
         * value allows:
         *   slookupswitch L3 2 35 L1 37 L2;
         */

        this.pairs = new TreeMap<>();
        this.defaultLabel = (short) Integer.parseInt(parameters.get(0).substring(1));
        this.npair = (short) Integer.parseInt(parameters.get(1));

        params.add((byte) ((this.defaultLabel >> 8) & 0x00FF));
        params.add((byte) this.defaultLabel);

        params.add((byte) ((this.npair >> 8) & 0x00FF));
        params.add((byte) this.npair);

        if (parameters.size() != (2 * this.npair + 2)) {
            throw new InvalidParameterException
                    (this.getOpcode() + " has invalid parameters size.");
        }

        for (int pair = 0; pair < (this.npair & 0x00FFFF); pair++) {
            short matchValue = (short) Integer.parseInt(parameters.get(2 * pair + 2));
            short offsetLabel = (short) Integer.parseInt(parameters.get(2 * pair + 3).substring(1));

            this.pairs.put(matchValue, offsetLabel);

            params.add((byte) ((matchValue >> 8) & 0x00FF));
            params.add((byte) matchValue);

            params.add((byte) 0); // fill by zero and update later
            params.add((byte) 0);
        }

        return params;
    }

    @Override
    public void updateLabels(ArrayList<Short> methodsLabels, ArrayList<Instruction> methodBytecodes, short methodOffset) {
        ArrayList<Byte> params = this.getParameters();

        int index = 2 * Short.BYTES; // defaultLabel & npair
        int labelValue = 0;

        for (short foo = 0; foo < methodsLabels.get(this.defaultLabel); foo++) {
            labelValue += methodBytecodes.get(foo).getInstructionSize();
        }

        labelValue = labelValue - methodOffset;
        params.set(0, (byte) ((labelValue >> 8) & 0x00FF));
        params.set(1, (byte) labelValue);

        Set set = this.pairs.entrySet();
        Iterator iterator = set.iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            short offsetLabel = (short) entry.getValue();
            labelValue = 0;

            index += Short.BYTES; // matchValue

            for (short foo = 0; foo < methodsLabels.get(offsetLabel); foo++) {
                labelValue += methodBytecodes.get(foo).getInstructionSize();
            }

            labelValue = labelValue - methodOffset;

            params.set(index, (byte) ((labelValue >> 8) & 0x00FF));
            index++;
            params.set(index, (byte) labelValue);
            index++;
        }
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append(super.toString());

        // default label
        out.append(" L" + this.defaultLabel);
        out.append(" " + this.npair);

        Set set = this.pairs.entrySet();
        Iterator iterator = set.iterator();

        while (iterator.hasNext()) {
            Map.Entry entry = (Map.Entry) iterator.next();
            out.append(" (" + entry.getKey() + " L" + entry.getValue() + ")");
        }

        return out.toString();
    }

}
