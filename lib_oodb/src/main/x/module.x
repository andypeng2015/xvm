/**
 * This module contains the Object Oriented Database (OODB) APIs.
 */
module oodb.xtclang.org
    {
    typedef (DBInvoke<<>, <Boolean>> | function Boolean()) Condition;

    /**
     * A `Permission` represents a targeted action that can be allowed (permitted) or disallowed
     * (revoked).
     */
    const Permission(String target, String action)
        {
        /**
         * A wild-card representing all targets (database objects) that a permission may apply to.
         */
        static String AllTargets = "*";

        /**
         * A wild-card representing all actions (database functions) that a permission may apply to.
         */
        static String AllActions = "*";
        }

    /**
     * This mixin is used to mark a module as being a database module.
     */
    mixin Database
            into Module
        {
        }
    }
