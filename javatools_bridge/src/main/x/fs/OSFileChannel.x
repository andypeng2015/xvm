import ecstasy.fs.FileChannel;
import ecstasy.io.Buffer;

/**
 * Native OS FileChannel implementation.
 */
service OSFileChannel
        implements FileChannel
    {
    // ----- FileChannel API -----------------------------------------------------------------------

    @Override
    Int size.get()
        {TODO("native");}

    @Override
    Int position.get()
        {TODO("native");}

    @Override
    void flush()
        {TODO("native");}


    // ----- Channel API ---------------------------------------------------------------------------

    @Override
    @RO Boolean readable.get()
        {TODO("native");}

    @Override
    conditional Int read(Buffer<Byte> buffer, Int minBytes = Int.maxvalue)
        {TODO("native");}

    @Override
    conditional (Int, Int) read(Buffer<Byte>[] buffers, Int minBytes = Int.maxvalue)
        {TODO("native");}

    @Override
    @RO Boolean writable.get()
        {TODO("native");}

    @Override
    Int write(Buffer<Byte> buffer)
        {TODO("native");}

    @Override
    (Int, Int) write(Buffer<Byte>[] buffers)
        {TODO("native");}


    // ----- Closeable API -------------------------------------------------------------------------

    @Override
    void close(Exception? cause = Null)
        {TODO("native");}
    }
