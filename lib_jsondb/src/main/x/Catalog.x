import model.Lock;
import model.SysInfo;

/**
 * Metadata catalog for a database. A `Catalog` acts as the "gateway" to a JSON database, allowing a
 * database to be created, opened, examined, recovered, upgraded, and/or deleted.
 *
 * A `Catalog` is instantiated as a combination of a database module which provides the model (the
 * Ecstasy representation) for the database, and a filing system directory providing the storage for
 * the database's data. The `Catalog` does not require the module to be provided; it can be omitted
 * so that a database on disk can be examined and (to a limited extent) manipulated/repaired without
 * explicit knowledge of its Ecstasy representation.
 *
 * The `Catalog` has a weak notion of mutual exclusion:
 *
 * * While the Catalog is [Configuring](Status.Configuring), [Running](Status.Running), or
 *   [Recovering](Status.Recovering), it
 *
 * TODO version - should only be able to open the catalog with the correct TypeSystem version
 */
service Catalog
        implements Closeable
    {
    // ----- constructors --------------------------------------------------------------------------

    /**
     * Open the catalog for the specified directory.
     *
     * @param dir       the directory that contains (or may contain) the catalog
     * @param dbModule  (optional) the Ecstasy module that represents the database schema
     * @param readOnly  (optional) pass `True` to access the catalog in a read-only manner
     */
    construct(Directory dir, Module? dbModule = Null, Boolean readOnly = False)
        {
        assert:arg dir.exists && dir.readable && (readOnly || dir.writable);

        @Inject Clock clock;

        this.timestamp = clock.now;
        this.dir       = dir;
        this.readOnly  = readOnly;
        this.dbModule  = dbModule;
        this.status    = Closed;
        }


    // ----- properties ----------------------------------------------------------------------------

    /**
     * The timestamp from when this Catalog was created; used as an assumed-unique identifier.
     */
    public/private DateTime timestamp;

    /**
     * The directory used to store the contents of the database
     */
    public/private Directory dir;

    /**
     * True iff the database was opened in read-only mode.
     */
    public/private Boolean readOnly;

    /**
     * The module representing the database. Used for serialization and deserialization of
     * persistent data.
     */
    public/private Module? dbModule;

    /**
     * The version of the database represented by this `Catalog` object. The version may not be
     * available before the database is opened.
     */
    public/private Version? version;

    /**
     * The status of this `Catalog` object.
     */
    @Atomic public/private Status status;


    // ----- visibility ----------------------------------------------------------------------------

    @Override
    String toString()
        {
// TODO GG: return $"{this:class.name}:\{dir={dir}, version={version}, status={status}, readOnly={readOnly}, unique-id={timestamp}}";
        return $"Catalog:\{dir={dir}, version={version}, status={status}, readOnly={readOnly}, unique-id={timestamp}}";
        }


    // ----- status management ---------------------------------------------------------------------

    /**
     * The file used to store the "in-use" status for the database.
     */
    @Lazy File statusFile.calc()
        {
        return dir.fileFor("sys.json");
        }

    /**
     * The status of this `Catalog`.
     *
     * * `Closed` - This `Catalog` object has not yet been opened, or it has been shut down.
     * * `Configuring` - This `Catalog` object has the database open for schema definition and
     *   modification, or other maintenance work.
     * * `Running` - This `Catalog` object has the database open for data access.
     * * `Recovering` - This `Catalog` object has been instructed to recover the database.
     */
    enum Status {Closed, Recovering, Configuring, Running}

    /**
     * For an empty `Catalog` that is `Closed`, initialize the directory and file structures so that
     * a catalog exists in the previously specified directory. After creation, the `Catalog` will be
     * in the `Configuring` status, allowing the caller to populate the database schema.
     *
     * @param name  the name of the database to create
     *
     * @throws IllegalState  if the Catalog is not `Empty`, or is read-only
     */
    void create(String name)
        {
        transition(Closed, Configuring, snapshot -> snapshot.empty);

        // TODO maybe return a config API?
        }

    /**
     * For an existent database, if this `Catalog` is `Closed`, `Recovering`, or `Running`, then
     * transition to the `Configuring` state, allowing modifications to be made to the database
     * structure.
     *
     * @throws IllegalState  if the Catalog is not `Closed` or `Running`, or is read-only
     */
    void edit()
        {
        transition([Closed, Recovering, Running], Configuring, snapshot -> !snapshot.empty && !snapshot.lockedOut);

        // TODO maybe return a config API?
        }

    /**
     * For an existent database, if this `Catalog` is locked-out, then assume that the previous
     * owner terminated, take ownership of the database and verify its integrity.
     *
     * @throws IllegalState  if the Catalog is not locked-out or `Closed`
     */
    void recover()
        {
        transition(Closed, Recovering, snapshot -> !snapshot.empty || sysDir.exists, ignoreLock = True);

        // TODO
        }

    /**
     * For an existent database, if this `Catalog` is `Closed`, `Recovering`, or `Configuring`, then
     * transition to the `Running` state, allowing access and modification of the database contents.
     *
     * @throws IllegalState  if the Catalog is not `Closed`, `Recovering`, or `Configuring`
     */
    void open()
        {
        transition([Closed, Recovering, Configuring], Running,
                snapshot -> snapshot.owned || snapshot.unowned,
                allowReadOnly = True);

        // TODO
        }

    /**
     * Close this `Catalog`.
     */
    @Override
    void close(Exception? cause = Null)
        {
        switch (status)
            {
            case Configuring:
            case Recovering:
                transition(status, Closed, snapshot -> snapshot.owned);
                break;

            case Running:
            case Closed:
                transition(status, Closed, snapshot -> snapshot.owned, allowReadOnly = True);
                break;

            default:
                assert;
            }
        }

    /**
     * For a `Catalog` that is `Configuring` or `Closed`, remove the entirety of the database. When
     * complete, the status will be `Closed`.
     *
     * @throws IllegalState  if the Catalog is not `Configuring` or `Closed`, or is read-only
     */
    void delete()
        {
        transition([Closed, Configuring], Configuring, snapshot -> snapshot.owned || snapshot.unowned);

        for (Directory subdir : dir.dirs())
            {
            subdir.deleteRecursively();
            }

        for (File file : dir.files())
            {
            file.delete();
            }

        transition(status, Closed, snapshot -> snapshot.owned);
        }

    /**
     * Validate that the current status matches the required status, optionally verify that the
     * Catalog is not read-only, and then with a lock in place, verify that the disk image also
     * matches that assumption. While holding that lock, optionally perform an operation, and then
     * update the status to the specified ,  (and the cor
     *
     * @param requiredStatus  one or more valid starting `Status` values
     * @param requiresWrite   `True` iff the Catalog is not allowed to be read-only
     * @param targetStatus    the ending `Status` to transition to
     * @param performAction   a function to execute while the lock is held
     *
     * @return True if the status has been changed
     */
    protected void transition(Status | Status[]         requiredStatus,
                              Status                    targetStatus,
                              function Boolean(Glance)? canTransition = Null,
                              Boolean                   allowReadOnly = False,
                              Boolean                   ignoreLock    = False)
        {
        Status oldStatus = status;
        if (requiredStatus.is(Status))
            {
            assert oldStatus == requiredStatus;
            }
        else
            {
            assert requiredStatus.contains(oldStatus);
            }

        if (readOnly)
            {
            assert allowReadOnly;
            status = targetStatus;
            }
        else
            {
            using (val lock = lock(ignoreLock))
                {
                // get a glance at the current status on disk, and verify that the requested
                // transition is legal
                Glance glance = glance();
                if (!canTransition?(glance))
                    {
                    throw new IllegalState($"Unable to transition {dir.path} from {oldStatus} to {targetStatus}");
                    }

                // store the updated status
                status = targetStatus;

                statusFile.contents = toBytes(new SysInfo(this));
                }
            }
        }


    // ----- directory Glance ----------------------------------------------------------------------

    /**
     * A `Glance` is a snapshot view of the database status on disk, from the point of view of the
     * `Catalog` that makes the "glancing" observation of the directory containing the database.
     */
    const Glance(SysInfo? info, Lock? lock, Exception? error)
        {
        /*
         * True iff at the moment of the snapshot, the observing `Catalog` detected that the
         * directory did not appear to contain a configured database.
         */
        Boolean empty.get()
            {
            return error == Null && info == Null;
            }

        /**
         * True iff at the moment of the snapshot, the observing `Catalog` detected that the
         * directory was not owned.
         */
        Boolean unowned.get()
            {
            return error == Null && (info?.status == Closed : True);
            }

        /**
         * True iff at the moment of the snapshot, the observing `Catalog` detected that it (and
         * not some other `Catalog` instance) was the owner of the directory.
         */
        Boolean owned.get()
            {
            return error == Null && info?.status != Closed && info?.stampedBy == this.Catalog.timestamp : False;
            }

        /**
         * True iff at the moment of the snapshot, that the observing `Catalog` detected the
         * _possibility_ that the directory has already been opened by another `Catalog` instance,
         * and is currently in use. (It is also possible that the directory was open previously,
         * and a clean shut-down did not occur.)
         */
        Boolean lockedOut.get()
            {
            return error != Null || (info?.status != Closed && info?.stampedBy != this.Catalog.timestamp : False);
            }
        }

    /**
     * Create a snapshot `Glance` of the status of the database on disk.
     *
     * @return a point-in-time snap-shot of the status of the database on disk
     */
    Glance glance()
        {
        SysInfo?   info  = Null;
        Lock?      lock  = Null;
        Exception? error = Null;

        import ecstasy.fs.FileNotFound;

        Byte[]? bytes = Null;
        try
            {
            if (lockFile.exists)
                {
                // this is not an atomic operation, so a FileNotFound may still occur
                bytes = lockFile.contents;
                }
            }
        catch (FileNotFound e)
            {
            // it's ok for the lock file to not exist
            }
        catch (Exception e)
            {
            error = e;
            }

        try
            {
            lock = fromBytes(Lock, bytes?);
            }
        catch (Exception e)
            {
            error ?:= e;
            }

        bytes = Null;
        try
            {
            if (statusFile.exists)
                {
                // this is not an atomic operation, so a FileNotFound may still occur
                bytes = statusFile.contents;
                }
            }
        catch (FileNotFound e)
            {
            // it's ok for the status file to not exist
            }
        catch (Exception e)
            {
            error ?:= e;
            }

        try
            {
            info = fromBytes(SysInfo, bytes?);
            }
        catch (Exception e)
            {
            error ?:= e;
            }

        return new Glance(info, lock, error);
        }


    // ----- catalog lock and status file management -----------------------------------------------

    /**
     * The file used to indicate a short-term lock.
     */
    @Lazy File lockFile.calc()
        {
        return dir.fileFor("sys.lock");
        }

    @Lazy Directory sysDir.calc()
        {
        return dir.dirFor("sys");
        }

    protected Closeable lock(Boolean ignorePreviousLock)
        {
        String           path  = lockFile.path.toString();
        Lock             lock  = new Lock(this);
        immutable Byte[] bytes = toBytes(lock);

        if (lockFile.exists && !ignorePreviousLock)
            {
            String msg = $"Lock file ({path}) already exists";
            try
                {
                Byte[] oldBytes = lockFile.contents;
                String text     = oldBytes.all(b -> b >= 32 && b <= 127 || new Char(b).isWhitespace())
                    ? new String(new Char[oldBytes.size](i -> new Char(oldBytes[i])))
                    : oldBytes.toString();
                msg = $"{msg}; Catalog timestamp={timestamp}; lock file contains: {text}";
                }
            catch (Exception e)
                {
                throw new IllegalState(msg, e);
                }

            throw new IllegalState(msg);
            }

        if (!lockFile.create() && !ignorePreviousLock)
            {
            throw new IllegalState($"Failed to create lock file: {path}");
            }

        try
            {
            lockFile.contents = bytes;
            }
        catch (Exception e)
            {
            throw new IllegalState($"Failed to write lock file: {path}", e);
            }

        return new Closeable()
            {
            @Override void close(Exception? cause = Null)
                {
                lockFile.delete();
                }
            };
        }
    }
