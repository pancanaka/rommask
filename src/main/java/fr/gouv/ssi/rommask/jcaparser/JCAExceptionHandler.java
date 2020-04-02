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
 * JCA file Exception Handler class
 *
 * @author Guillaume Bouffard
 */
public class JCAExceptionHandler {

    /**
     * start offset of the exception in the Method component
     */
    private short startOffset;

    /**
     * end offset of the exception in the Method component
     */
    private short endOffset;

    /**
     * Offset of the catch statement managed by this handler
     */
    private short handlerOffset;

    /**
     * Offset in the constant pool component of the caught exception
     */
    private short catchTypeIndex;

    /**
     * Class constructor
     *
     * @param startOffset    label where try-statement begins
     * @param endOffset      label where try-statement ends
     * @param handlerOffset  catch-statement label
     * @param catchTypeIndex throwable caught type
     */
    public JCAExceptionHandler(short startOffset, short endOffset, short handlerOffset, short catchTypeIndex) {
        this.startOffset = startOffset;
        this.endOffset = endOffset;
        this.handlerOffset = handlerOffset;
        this.catchTypeIndex = catchTypeIndex;
    }

    /**
     * Get try-statement begins label
     *
     * @return try-statement begins label
     */
    public short getStartOffset() {
        return startOffset;
    }

    /**
     * Set try-statement begins label
     *
     * @param startOffset try-statement begins label
     */
    public void setStartOffset(short startOffset) {
        this.startOffset = startOffset;
    }

    /**
     * Set try-statement begins label
     *
     * @return try-statement begins label
     */
    public short getEndOffset() {
        return endOffset;
    }

    /**
     * Get try-statement ends label
     *
     * @param endOffset try-statement ends label
     */
    public void setEndOffset(short endOffset) {
        this.endOffset = endOffset;
    }

    /**
     * Get catch-statement label
     *
     * @return catch-statement label
     */
    public short getHandlerOffset() {
        return handlerOffset;
    }

    /**
     * Set catch-statement label
     *
     * @param handlerOffset catch-statement label
     */
    public void setHandlerOffset(short handlerOffset) {
        this.handlerOffset = handlerOffset;
    }

    /**
     * Get throwable caught type
     *
     * @return throwable caught type
     */
    public short getCatchTypeIndex() {
        return catchTypeIndex;
    }

    /**
     * Set throwable caught type
     *
     * @param catchTypeIndex throwable caught type
     */
    public void setCatchTypeIndex(short catchTypeIndex) {
        this.catchTypeIndex = catchTypeIndex;
    }

    /**
     * Check if the current exception handler is included in the one given in parameter
     *
     * @param exceptionHandler the exception handler included the current one?
     * @return true if the current exception handler is included in the one given in parameter
     */
    public boolean isIncludedIn(JCAExceptionHandler exceptionHandler) {
        return ((this.getStartOffset() >= exceptionHandler.getStartOffset())
                && (this.getEndOffset() <= exceptionHandler.getEndOffset()));
    }
}
