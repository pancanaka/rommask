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
 * Instruction with byte parameter meta class
 *
 * @author Guilalume Bouffard
 */
public abstract class InstructionWithBytesParameter extends Instruction {

    /**
     * Class constructor with parameters
     *
     * @param opcode     opcode value
     * @param parameters instruction parameters list
     */
    public InstructionWithBytesParameter(Bytecode opcode, ArrayList<String> parameters) throws InvalidParameterException {
        super(opcode, parameters);
    }

}
