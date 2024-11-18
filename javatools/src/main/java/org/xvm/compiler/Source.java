package org.xvm.compiler;


import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import java.util.Arrays;
import java.util.NoSuchElementException;

import org.xvm.tool.ModuleInfo.FileNode;


import static org.xvm.compiler.Lexer.isLineTerminator;

import static org.xvm.util.Handy.appendString;
import static org.xvm.util.Handy.checkReadable;
import static org.xvm.util.Handy.hexitValue;
import static org.xvm.util.Handy.isHexit;
import static org.xvm.util.Handy.readFileBytes;
import static org.xvm.util.Handy.readFileChars;


/**
 * A representation of an Ecstasy source code file, handling the first two phases of lexical analysis
 * (line termination, location and Unicode escapes).
 */
public class Source
        implements Constants, Cloneable
    {
    // ----- constructors --------------------------------------------------------------------------

    /**
     * Construct a Source directly from a String of Ecstasy source code.
     *
     * @param sScript  the Ecstasy source code, as a String
     */
    public Source(String sScript)
        {
        this(sScript.toCharArray());
        }

    /**
     * Construct a Source by reading the Ecstasy source code from a file.
     *
     * @param file the File containing the Ecstasy source code to load
     *
     * @throws IOException
     */
    public Source(File file)
            throws IOException
        {
        this(readFileChars(file));
        m_file = file;
        }

    /**
     * Construct a Source object that represents the source code associated with the specified Node
     * originating from a ModuleInfo. This constructor allows the Source object to access the
     * resource directories and files that are associated with the source code by the ModuleInfo.
     *
     * @param node  a Node that came from a ModuleInfo
     */
    public Source(FileNode node)
        {
        m_file = node.file();
        m_ach  = node.content();
        m_cch  = m_ach.length;
        m_node = node;
        }

    /**
     * Construct a Source from an input stream.
     *
     * @param stream  the InputStream
     */
    public Source(InputStream stream)
        {
        this(fromInputStream(stream));
        }

    /**
     * Read a char[] from a stream. Inefficient, but predictable.
     *
     * @param stream  the stream to vacuum
     *
     * @return the contents of the stream, as a char[]
     */
    private static char[] fromInputStream(InputStream stream)
        {
        try
            {
            StringBuilder sb = new StringBuilder();
            int n;
            while ((n = stream.read()) >= 0)
                {
                sb.append((char) n);
                }
            return sb.toString().toCharArray();
            }
        catch (IOException e)
            {
            throw new RuntimeException(e);
            }
        }

    /**
     * Construct a Source directly from a character array containing the Ecstasy
     * source code. Note that the passed array is retained -- not copied! -- by
     * this constructor.
     *
     * @param ach  the Ecstasy source code, as a character array
     */
    Source(char[] ach)
        {
        assert ach != null;
        m_ach = ach;
        m_cch = ach.length;
        }


    // ----- public API ----------------------------------------------------------------------------

    /**
     * @return the file name, if one has been configured
     */
    public String getFileName()
        {
        if (m_sFile == null && m_file != null)
            {
            m_sFile = m_file.getPath();
            }

        return m_sFile;
        }

    /**
     * @return the simple file name, if a file is available
     */
    public String getSimpleFileName()
        {
        return m_file == null ? "<no file>" : m_file.getName();
        }

    /**
     * Determine the File referenced from inside another source file using the "File" or "Dir"
     * BNF constructions.
     *
     * @param sFile  a string put together from identifier tokens, "." tokens, "/" tokens, "./"
     *               tokens, and "../" tokens, following the rules defined in the Ecstasy BNF
     *
     * @return a File, a ResourceDir, or null if unresolvable
     */
    public Object resolvePath(String sFile)
        {
        return sFile != null && !sFile.isEmpty() && m_node != null
                ? m_node.resolveResource(sFile)
                : null;
        }

    /**
     * Load a file (as text) referenced from inside another source file.
     *
     * @param sFile  a string put together from identifier tokens, "/" tokens, "./" tokens, and
     *               "../" tokens
     *
     * @return the Source, or null
     */
    public Source includeString(String sFile)
            throws IOException
        {
        Object resource = resolvePath(sFile);
        if (resource instanceof File file && checkReadable(file))
            {
            return new Source(file);
            }

        return null;
        }

    /**
     * Load a file (as binary) referenced from inside another source file.
     *
     * @param sFile  a string put together from identifier tokens, "/" tokens, "./" tokens, and
     *               "../" tokens
     *
     * @return the binary contents of the file, or null
     */
    public byte[] includeBinary(String sFile)
            throws IOException
        {
        Object resource = resolvePath(sFile);
        if (resource instanceof File file && checkReadable(file))
            {
            return readFileBytes(file);
            }

        return null;
        }

    /**
     * Determine if there are more characters in the source.
     *
     * @return true iff there are still more characters
     */
    public boolean hasNext()
        {
        return m_of < m_cch;
        }

    /**
     * Obtain the next character of the source. Note that Unicode escapes are
     * processed such that the sequence of characters "U+0024" in the source
     * would return only the single character '$'. Similarly, the combination
     * of CR+LF ("\r\n") is returned as the single character LF ('\n').
     *
     * @return the next character from the source
     *
     * @throws NoSuchElementException  if an attempt is made to advance past
     *         the end
     */
    public char next()
        {
        final char[] ach = m_ach;
        final int    cch = m_cch;

        int of = m_of;
        if (of >= cch)
            {
            throw new NoSuchElementException();
            }

        char ch = ach[of++];

        // check for new line
        if (Lexer.isLineTerminator(ch))
            {
            // handle the special case of CR:LF by treating it as a single LF
            // character
            if (ch == '\r' && of < cch && ach[of] == '\n')
                {
                ++of;
                ch = '\n';
                }

            ++m_iLine;
            m_iLineOffset = 0;
            }
        else
            {
            int cchAdjust = 1;

            // check for a Unicode escape
            if (ch == '\\' && of + 4 < cch
                    && isHexit(ach[of+1])
                    && isHexit(ach[of+2])
                    && isHexit(ach[of+3])
                    && isHexit(ach[of+4]))
                {
                final char chU = ach[of];
                if (chU == 'u')
                    {
                    // 4-hexit unicode escape
                    int nch = hexitValue(ach[of+1]) << 12
                            | hexitValue(ach[of+2]) << 8
                            | hexitValue(ach[of+3]) << 4
                            | hexitValue(ach[of+4]);

                    ch = (char) nch;
                    of        += 5;
                    cchAdjust += 5;
                    m_fEscapesEncountered = true;
                    }
                else if (chU == 'U' && of + 8 < cch
                        && isHexit(ach[of+5])
                        && isHexit(ach[of+6])
                        && isHexit(ach[of+7])
                        && isHexit(ach[of+8]))
                    {
                    // 8-hexit unicode escape
                    int nch = hexitValue(ach[of+1]) << 28
                            | hexitValue(ach[of+2]) << 24
                            | hexitValue(ach[of+3]) << 20
                            | hexitValue(ach[of+4]) << 16
                            | hexitValue(ach[of+5]) << 12
                            | hexitValue(ach[of+6]) << 8
                            | hexitValue(ach[of+7]) << 4
                            | hexitValue(ach[of+8]);

                    // unfortunately Java does not support characters with codepoints beyond 16
                    // bits; we could theoretically split this up into a Unicode "surrogate pair",
                    // but that is not supported by this class at this time
                    ch  = nch > Character.MAX_VALUE ? '?' : (char) nch;
                    of        += 9;
                    cchAdjust += 9;
                    m_fEscapesEncountered = true;
                    }
                }

            // a negative line offset indicates that the offset is not currently
            // being tracked because a line terminator was put back
            if (m_iLineOffset >= 0)
                {
                m_iLineOffset += cchAdjust;
                }
            }

        m_of = of;
        return ch;
        }

    /**
     * Undo a previously made call to the {@link #next()} method by "rewinding"
     * one character. In parsing terminology, this is often referred to as a
     * "put back char" operation.
     *
     * @throws NoSuchElementException  if an attempt is made to rewind past the
     *         beginning
     */
    public void rewind()
        {
        int of = m_of;
        if (of <= 0)
            {
            throw new NoSuchElementException();
            }

        // determine what the immediately preceding character was
        --of;
        final char[] ach = m_ach;
        final char   ch  = ach[of];
        // if the line feed is immediately preceded by a carriage return, then
        // back up past them both (they are treated as a single line feed)
        if (isLineTerminator(ch))
            {
            if (ch == '\n' && of > 0 && ach[of-1] == '\r')
                {
                --of;
                }

            --m_iLine;

            // instead of determining the line offset in the previous line that
            // we just rewound to, defer the calculation until it is needed
            m_iLineOffset = -1;
            }
        else
            {
            int cchAdjust = 1;

            if (m_fEscapesEncountered
                    && isHexit(ch) && of >= 5
                    && isHexit(ach[of-1])
                    && isHexit(ach[of-2])
                    && isHexit(ach[of-3]))
                {
                if (ach[of-5] == '\\' && ach[of-4] == 'u')
                    {
                    of        -= 5;
                    cchAdjust += 5;
                    }
                else if (of >= 9 && ach[of-9] == '\\' && ach[of-8] == 'U'
                        && isHexit(ach[of-7])
                        && isHexit(ach[of-6])
                        && isHexit(ach[of-5])
                        && isHexit(ach[of-4]))
                    {
                    of        -= 9;
                    cchAdjust += 9;
                    }
                }

            // a negative line offset indicates that the offset is not currently
            // being tracked because a line terminator was put back
            if (m_iLineOffset >= 0)
                {
                m_iLineOffset -= cchAdjust;
                }
            }

        m_of = of;
        }

    /**
     * Determine the current line number within the source.
     *
     * @return the zero-based line number
     */
    public int getLine()
        {
        return m_iLine;
        }

    /**
     * Determine the offset within the current line of the source.
     *
     * @return the zero-based offset within the current line
     */
    public int getOffset()
        {
        int iLineOffset = m_iLineOffset;
        if (iLineOffset < 0)
            {
            // go back until a line terminator is found
            iLineOffset = 0;
            for (int of = m_of; of > 0; )
                {
                if (isLineTerminator(m_ach[--of]))
                    {
                    break;
                    }

                ++iLineOffset;
                }

            m_iLineOffset = iLineOffset;
            }

        return iLineOffset;
        }

    /**
     * Obtain a token that represents the current location within the source.
     *
     * @return a position token
     */
    public long getPosition()
        {
        // use the line-offset accessor to force the re-calculation if necessary
        final int iLineOffset = getOffset();

        // up to 24 bits for offset, 20 bits for line and line offset
        assert m_of >= 0;
        assert m_iLine >= 0;
        assert iLineOffset >= 0;
        if (m_of > 0xFFFFFF || m_iLine > 0xFFFFF || iLineOffset >= 0xFFFFF)
            {
            throw new IllegalStateException();
            }

        return    (((long) m_of        & 0xFFFFFF) << 40)
                | (((long) m_iLine     & 0x0FFFFF) << 20)
                | (((long) iLineOffset & 0x0FFFFF)      );
        }

    /**
     * Using a previously returned position token, set the current position
     * within the source to the position indicated by the token.
     *
     * @param lPosition  a previously returned position token
     */
    public void setPosition(long lPosition)
        {
        m_of          = ((int) (lPosition >>> 40)) & 0xFFFFFF;
        m_iLine       = ((int) (lPosition >>> 20)) & 0x0FFFFF;
        m_iLineOffset = ((int) (lPosition       )) & 0x0FFFFF;
        }

    /**
     * Determine the line number from a previously returned position token.
     *
     * @param lPosition  a position token
     *
     * @return the zero-based line number of the specified position
     */
    public static int calculateLine(long lPosition)
        {
        return ((int) (lPosition >>> 20)) & 0x0FFFFF;
        }

    /**
     * Determine the offset within the line from a previously returned position
     * token.
     *
     * @param lPosition  a position token
     *
     * @return the zero-based offset within the line of the specified position
     */
    public static int calculateOffset(long lPosition)
        {
        return ((int) lPosition) & 0x0FFFFF;
        }

    /**
     * Obtain the string of characters starting from one position and proceeding
     * to another position. The current position is not affected by this method.
     *
     * @param lPositionFrom  a position token to start from (inclusive)
     * @param lPositionTo    a position token to end at (exclusive)
     *
     * @return the String of characters from the first to the second specified
     *         position
     */
    public String toString(long lPositionFrom, long lPositionTo)
        {
        long lPositionSave = getPosition();

        setPosition(lPositionFrom);
        final int ofEnd = ((int) (lPositionTo >>> 40)) & 0xFFFFFF;
        assert ofEnd >= m_of;
        char[] ach = new char[ofEnd - m_of];
        int    cch = 0;
        while (m_of < ofEnd)
            {
            ach[cch++] = next();
            }

        setPosition(lPositionSave);
        return new String(ach, 0, cch);
        }

    /**
     * @return a clone of this Source, but with the position reset to the beginning of the source
     *         code
     */
    public Source clone()
        {
        try
            {
            Source that = (Source) super.clone();
            that.reset();
            return that;
            }
        catch (CloneNotSupportedException e)
            {
            throw new RuntimeException(e);
            }
        }

    /**
     * Reset the position to the very beginning of the source code.
     */
    public void reset()
        {
        m_of          = 0;
        m_iLine       = 0;
        m_iLineOffset = 0;
        }

    /**
     * @return a String intended to make this usable in a debugger
     */
    public String toString()
        {
        long lCur = getPosition();

        String sIntro = "...";
        for (int i = 0; i < 20; ++i)
            {
            try
                {
                rewind();
                }
            catch (NoSuchElementException e)
                {
                sIntro = "";
                break;
                }
            }
        long lPre = getPosition();
        setPosition(lCur);

        String sEpilogue = "...";
        for (int i = 0; i < 20; ++i)
            {
            try
                {
                next();
                }
            catch (NoSuchElementException e)
                {
                sEpilogue = "(EOF)";
                break;
                }
            }
        long lPost = getPosition();
        setPosition(lCur);

        String sPre = toString(lPre, lCur);
        String sPost = toString(lCur, lPost);

        StringBuilder sb = new StringBuilder(sIntro);
        appendString(sb, sPre);
        char[] achIndent = new char[sb.length()];
        Arrays.fill(achIndent, ' ');

        appendString(sb, sPost)
          .append(sEpilogue)
          .append('\n')
          .append(new String(achIndent))
          .append('^');
        return sb.toString();
        }

    /**
     * Obtain the underlying data that the source represents.
     *
     * @return the whole of the unprocessed source, as a String
     */
    public String toRawString()
        {
        return new String(m_ach);
        }


    // ----- data members --------------------------------------------------------------------------

    /**
     * The source code.
     */
    private final char[] m_ach;

    /**
     * The length of the source code.
     */
    private final int m_cch;

    /**
     * The current offset within the source code.
     */
    private int m_of;

    /**
     * The current source code line number.
     */
    private int m_iLine;

    /**
     * The current offset within the current line of source code.
     */
    private int m_iLineOffset;

    /**
     * Set to true iff Unicode escapes have been encountered.
     */
    private boolean m_fEscapesEncountered;

    /**
     * The compiler ModuleInfo FileNode that this Source originates from.
     */
    private FileNode m_node;

    /**
     * The file name that the source comes from.
     */
    private String m_sFile;

    /**
     * The file that the source comes from.
     */
    private File m_file;
    }