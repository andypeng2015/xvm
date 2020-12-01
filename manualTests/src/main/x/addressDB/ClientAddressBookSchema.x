class ClientAddressBookSchema
        extends imdb.ClientRootSchema
        implements AddressBookSchema
        implements db.Connection<AddressBookSchema>
    {
    construct()
        {
        construct imdb.ClientRootSchema(ServerAddressBookSchema);
        }
    finally
        {
        contacts = new ClientContacts(ServerAddressBookSchema.contacts);
        }

    @Override
    @Unassigned Contacts contacts;

    @Override
    @Unassigned db.DBUser dbUser;

    @Override
    public/protected ClientAddressBookTransaction? transaction;

    @Override
    ClientAddressBookTransaction createTransaction(
                Duration? timeout = Null, String? name = Null,
                UInt? id = Null, db.DBTransaction.Priority priority = Normal,
                Int retryCount = 0)
        {
        ClientAddressBookTransaction tx = new ClientAddressBookTransaction();
        transaction = tx;
        return tx;
        }

    class ClientContacts
            extends imdb.ClientDBMap<String, Contact>
            incorporates Contacts
        {
        construct(ServerAddressBookSchema.ServerContacts contacts)
            {
            construct imdb.ClientDBMap(contacts);
            }

        // ----- Contacts mixin --------------------------------------------------------------------

        @Override
        void addContact(Contact contact)
            {
            (Boolean autoCommit, db.Transaction tx) = ensureTransaction();

            super(contact);

            if (autoCommit)
                {
                tx.commit();
                }
            }

        @Override
        void addPhone(String name, Phone phone)
            {
            (Boolean autoCommit, db.Transaction tx) = ensureTransaction();

            super(name, phone);

            if (autoCommit)
                {
                tx.commit();
                }
            }

        // ----- class specific --------------------------------------------------------------------

        protected (Boolean, db.Transaction) ensureTransaction()
            {
            ClientAddressBookTransaction? tx = this.ClientAddressBookSchema.transaction;
            return tx == Null
                    ? (True, createTransaction())
                    : (False, tx);
            }

        // ----- ClientDBMap interface ------------------------------------------------------------

        @Override
        Boolean autoCommit.get()
            {
            return this.ClientAddressBookSchema.transaction == Null;
            }

        @Override
        Tuple dbInvoke(String | Function fn, Tuple args = Tuple:(), (Duration|DateTime)? when = Null)
            {
            if (fn == "addPhone" && when == Null)
                {
                assert args.is(Tuple<String, Phone>);

                return addPhone(args[0], args[1]);
                }
            throw new UnsupportedOperation(fn.toString());
            }

        @Override
        class ClientChange
            {
            construct()
                {
                 // TODO CP - would be nice if it read "construct super();"
                construct imdb.ClientDBMap.ClientChange();
                }
            finally
                {
                ClientAddressBookTransaction? tx = this.ClientAddressBookSchema.transaction;
                assert tx != Null;
                tx.dbTransaction.contents.put("Contacts", this);
                }
            }
        }

    class ClientAddressBookTransaction
            extends imdb.ClientTransaction<AddressBookSchema>
            implements AddressBookSchema
        {
        construct()
            {
            construct imdb.ClientTransaction(
                ServerAddressBookSchema, ServerAddressBookSchema.createDBTransaction());
            }

        @Override
        db.SystemSchema sys.get()
            {
            TODO
            }

        @Override
        (db.Connection<AddressBookSchema> + AddressBookSchema) connection.get()
            {
            return this.ClientAddressBookSchema;
            }

        @Override
        Contacts contacts.get()
            {
            return this.ClientAddressBookSchema.contacts;
            }

        @Override
        Boolean pending.get()
            {
            return this.ClientAddressBookSchema.transaction == this;
            }

        @Override
        Boolean commit()
            {
            try
                {
                return super();
                }
            finally
                {
                this.ClientAddressBookSchema.transaction = Null;
                }
            }

        @Override
        void rollback()
            {
            try
                {
                super();
                }
            finally
                {
                this.ClientAddressBookSchema.transaction = Null;
                }
            }
        }
    }
