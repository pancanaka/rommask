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

import fr.xlim.ssd.capmanipulator.library.ExceptionHandlerInfo;

/**
 * Translate Exception handler info component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ExceptionHandlerInfoFromJCA extends ExceptionHandlerInfo implements ComponentUtils, Cloneable {

    /**
     * Exception class name
     */
    private String classname;
    /**
     * Exception method name
     */
    private String methodname;

    /**
     * Default constructor
     *
     * @param classname  exception class name
     * @param methodname exception method name
     */
    public ExceptionHandlerInfoFromJCA(String classname, String methodname) {
        this.classname = classname;
        this.methodname = methodname;
    }

    /**
     * Empty constructor
     */
    private ExceptionHandlerInfoFromJCA() {
    }

    /**
     * Get class name
     *
     * @return class name
     */
    public String getClassName() {
        return this.classname;
    }

    /**
     * Get method name
     *
     * @return method name
     */
    public String getMethodName() {
        return this.methodname;
    }

    /**
     * Get full method name
     *
     * @return full method name
     */
    public String getFullMethodName() {
        return this.methodname;
    }

    @Override
    public short computeComponentSize() {
        return Short.BYTES // start_offset
                + Short.BYTES // bitfield
                + Short.BYTES // handler_offset
                + Short.BYTES; // catch_type_index
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ExceptionHandlerInfoFromJCA out = new ExceptionHandlerInfoFromJCA();

        out.setStartOffset(this.getStartOffset());
        out.setStopBit(this.getStopBit());
        out.setActiveLength(this.getActiveLength());
        out.setHandlerOffset(this.getHandlerOffset());
        out.setCatchTypeIndex(this.getCatchTypeIndex());

        out.classname = this.classname;
        out.methodname = this.methodname;

        return out;
    }
}
