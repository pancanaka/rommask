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

import java.util.ArrayList;

/**
 * JCA method bytecode definition
 *
 * @author Guillaume Bouffard
 */
public class JCAMethodBytecodes {

    /**
     * Method stack size
     */
    private byte methodStack;

    /**
     * Number of method locals
     */
    private byte methodLocals;

    /**
     * List of method instructions
     */
    private ArrayList<Instruction> instructions;

    /**
     * List of methods label offsets
     */
    private ArrayList<Short> labels;

    /**
     * List of method exception handlers
     */
    private ArrayList<JCAExceptionHandler> exceptionsHandlers;

    /**
     * Default constructor
     *
     * @param methodStack  Method stack size
     * @param methodLocals Number of method locals
     */
    public JCAMethodBytecodes(byte methodStack, byte methodLocals) {
        this.methodStack = methodStack;
        this.methodLocals = methodLocals;

        this.instructions = new ArrayList<>();
        this.labels = new ArrayList<>();
        this.exceptionsHandlers = new ArrayList<>();
        this.exceptionsHandlers = new ArrayList<>();
    }

    /**
     * Get method max stack number
     *
     * @return method max stack number
     */
    public byte getMethodStack() {
        return methodStack;
    }

    /**
     * Set method max stack number
     *
     * @param methodStack method max stack number
     */
    public void setMethodStack(byte methodStack) {
        this.methodStack = methodStack;
    }

    /**
     * Get method locals number
     *
     * @return method locals number
     */
    public byte getMethodLocals() {
        return methodLocals;
    }

    /**
     * Set method locals number
     *
     * @param methodLocals method locals number
     */
    public void setMethodLocals(byte methodLocals) {
        this.methodLocals = methodLocals;
    }

    /**
     * Get method instructions
     *
     * @return method instructions
     */
    public ArrayList<Instruction> getInstructions() {
        return instructions;
    }

    /**
     * Set method instructions
     *
     * @param instructions method instructions
     */
    public void setInstructions(ArrayList<Instruction> instructions) {
        this.instructions = instructions;
    }

    /**
     * Get method exception handlers table
     *
     * @return method exception handlers table
     */
    public ArrayList<JCAExceptionHandler> getExceptionsHandlers() {
        return exceptionsHandlers;
    }

    /**
     * Set method exception handlers table
     *
     * @param exceptionsHandlers method exception handlers table
     */
    public void setExceptionsHandlers(ArrayList<JCAExceptionHandler> exceptionsHandlers) {
        this.exceptionsHandlers = exceptionsHandlers;
    }

    /**
     * Get labels list
     *
     * @return labels list
     */
    public ArrayList<Short> getLabels() {
        return labels;
    }

    /**
     * Set labels list
     *
     * @param labels labels list
     */
    public void setLabels(ArrayList<Short> labels) {
        this.labels = labels;
    }

}
