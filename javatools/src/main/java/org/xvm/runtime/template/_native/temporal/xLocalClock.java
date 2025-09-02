package org.xvm.runtime.template._native.temporal;


import java.util.Timer;
import java.util.TimerTask;

import org.xvm.asm.ClassStructure;
import org.xvm.asm.ConstantPool;
import org.xvm.asm.MethodStructure;
import org.xvm.asm.Op;

import org.xvm.asm.constants.TypeConstant;

import org.xvm.runtime.Container;
import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.ObjectHandle.GenericHandle;
import org.xvm.runtime.ServiceContext;
import org.xvm.runtime.TypeComposition;
import org.xvm.runtime.Utils;
import org.xvm.runtime.WeakCallback;

import org.xvm.runtime.template.xBoolean;
import org.xvm.runtime.template.xBoolean.BooleanHandle;
import org.xvm.runtime.template.xNullable;
import org.xvm.runtime.template.xService;

import org.xvm.runtime.template.collections.xArray;
import org.xvm.runtime.template.collections.xArray.Mutability;

import org.xvm.runtime.template.numbers.BaseInt128.LongLongHandle;
import org.xvm.runtime.template.numbers.LongLong;
import org.xvm.runtime.template.numbers.xInt64;
import org.xvm.runtime.template.numbers.xInt128;

import org.xvm.runtime.template._native.reflect.xRTFunction.FunctionHandle;
import org.xvm.runtime.template._native.reflect.xRTFunction.NativeFunctionHandle;


/**
 * Native implementation of a simple wall clock using Java's millisecond-resolution "System" clock.
 */
public class xLocalClock
        extends xService {
    public static xLocalClock INSTANCE;

    public xLocalClock(Container container, ClassStructure structure, boolean fInstance) {
        super(container, structure, false);

        if (fInstance) {
            INSTANCE = this;
        }
    }

    @Override
    public void initNative() {
        markNativeProperty("now");
        markNativeProperty("timezone");

        // LocalClock has two "schedule" methods and while one is a trivial default implementation,
        // it would execute on the LocalClock service that belongs to the native container.
        // As a result, the "alarm" handle would be proxied via FunctionProxyHandle, which would
        // keep a hard reference to the calling service and would "leak" that service unless the
        // caller explicitly cancelled.
        // To prevent that, we need to implement it natively, which would execute the "schedule"
        // method on the caller's context and avoid creation of the alarm proxy.
        markNativeMethod("schedule",  new String[]{"temporal.Duration", "temporal.Clock.Alarm", "Boolean"}, null);
        markNativeMethod("schedule",  new String[]{"temporal.Time"    , "temporal.Clock.Alarm", "Boolean"}, null);

        invalidateTypeInfo();
    }

    @Override
    public TypeConstant getCanonicalType() {
        return pool().ensureEcstasyTypeConstant("temporal.Clock");
    }

    @Override
    public int invokeNativeGet(Frame frame, String sPropName, ObjectHandle hTarget, int iReturn) {
        switch (sPropName) {
        case "now":
            return frame.assignValue(iReturn, timeNow(frame));

        case "timezone":
            return frame.assignValue(iReturn, timezone(frame));
        }

        return super.invokeNativeGet(frame, sPropName, hTarget, iReturn);
    }

    @Override
    public int invokeNativeN(Frame frame, MethodStructure method,
                             ObjectHandle hTarget, ObjectHandle[] ahArg, int iReturn) {
        switch (method.getName()) {
        case "schedule": {
            GenericHandle  hWakeup = (GenericHandle)  ahArg[0];
            FunctionHandle hAlarm  = (FunctionHandle) ahArg[1];
            BooleanHandle  hKeep   = ahArg[2] instanceof BooleanHandle hB ? hB : xBoolean.FALSE;
            long           ldtNow  = frame.f_context.f_container.currentTimeMillis();
            long           ldtWakeup;
            long           cDelay;
            if (hWakeup.getType().equals(frame.poolContext().typeDuration())) {
                // hWakeUp is "Duration"
                LongLong llPicos = ((LongLongHandle) hWakeup.getField(null, "picoseconds")).getValue();

                cDelay    = llPicos.divUnsigned(xNanosTimer.PICOS_PER_MILLI).getLowValue();
                ldtWakeup = ldtNow + cDelay;
            } else {
                // hWakeUp is "Time"
                LongLong llEpoch = ((LongLongHandle) hWakeup.getField(null, "epochPicos")).getValue();

                ldtWakeup = llEpoch.divUnsigned(xNanosTimer.PICOS_PER_MILLI).getLowValue();
                cDelay    = Math.max(0, ldtWakeup - ldtNow);
            }

            return invokeSchedule(frame, ldtWakeup, cDelay, hAlarm, hKeep, iReturn);
        }
        }

        return super.invokeNativeN(frame, method, hTarget, ahArg, iReturn);
    }

    /**
     * Native implementation of
     *  "Cancellable schedule(Time     when, Alarm alarm, Boolean keepAlive = False)" and
     *  "Cancellable schedule(Duration delay, Alarm alarm, Boolean keepAlive = False)"
     */
    private int invokeSchedule(Frame frame, long ldtWakeup, long cDelay,
                               FunctionHandle hAlarm, BooleanHandle hKeepAlive, int iReturn) {
        Alarm alarm = new Alarm(new WeakCallback(frame, hAlarm), ldtWakeup, hKeepAlive.get());
        try {
            TIMER.schedule(alarm.getTrigger(), cDelay);
        } catch (Exception e) {
            alarm.cancel();
            return frame.raiseException(e.getMessage());
        }

        FunctionHandle hCancel = new NativeFunctionHandle((_frame, _ah, _iReturn) -> {
            alarm.cancel();
            return Op.R_NEXT;
        });

        return frame.assignValue(iReturn, hCancel);
    }

    /**
     * Injection support.
     */
    public ObjectHandle ensureLocalClock(Frame frame, ObjectHandle hOpts) {
        ObjectHandle hClock = m_hLocalClock;
        if (hClock == null) {
            m_hLocalClock = hClock = createServiceHandle(
                f_container.createServiceContext("LocalClock"),
                    getCanonicalClass(), getCanonicalType());
        }

        return hClock;
    }

    public ObjectHandle ensureDefaultClock(Frame frame, ObjectHandle hOpts) {
        // TODO
        return ensureLocalClock(frame, hOpts);
    }

    public ObjectHandle ensureUTCClock(Frame frame, ObjectHandle hOpts) {
        // TODO
        return ensureLocalClock(frame, hOpts);
    }


    // -----  helpers ------------------------------------------------------------------------------

    protected GenericHandle timeNow(Frame frame) {
        TypeComposition clzTime = ensureTimeClass();
        GenericHandle   hTime   = new GenericHandle(clzTime);

        LongLong llNow = new LongLong(frame.f_context.f_container.currentTimeMillis()).
                            mul(xNanosTimer.PICOS_PER_MILLI_LL);
        hTime.setField(frame, "epochPicos", xInt128.INSTANCE.makeHandle(llNow));
        hTime.setField(frame, "timezone", timezone(frame));
        hTime.makeImmutable();

        return hTime;
    }

    protected GenericHandle timezone(Frame frame) {
        GenericHandle hTimeZone = m_hTimeZone;
        if (hTimeZone == null) {
            ConstantPool    pool           = pool();
            ClassStructure  structTimeZone = f_container.getClassStructure("temporal.TimeZone");
            TypeConstant    typeTimeZone   = structTimeZone.getCanonicalType();
            TypeComposition clzTimeZone    = typeTimeZone.ensureClass(frame);

            ClassStructure  structRule     = (ClassStructure) structTimeZone.getChild("Rule");
            TypeConstant    typeRule       = structRule.getCanonicalType();
            TypeConstant    typeRuleArray  = pool.ensureArrayType(typeRule);
            TypeComposition clzRuleArray   = typeRuleArray.ensureClass(frame);

            m_hTimeZone = hTimeZone = new GenericHandle(clzTimeZone);

            long lOffset = 0; // TODO CP
            hTimeZone.setField(frame, "picos", xInt64.makeHandle(lOffset));
            hTimeZone.setField(frame, "name",  xNullable.NULL);
            hTimeZone.setField(frame, "rules", xArray.createEmptyArray(clzRuleArray, 0, Mutability.Mutable));
            hTimeZone.makeImmutable();
        }

        return hTimeZone;
    }

    protected TypeComposition ensureTimeClass() {
        TypeComposition clz = m_clzTime;
        if (clz == null) {
            clz = m_clzTime =
                f_container.getTemplate("temporal.Time").getCanonicalClass();
        }
        return clz;
    }

    /**
     * Represents a pending alarm.
     */
    protected static class Alarm {
        /**
         * Construct an alarm.
         *
         * @param refCallback  the weak ref to a function to call when the alarm triggers
         * @param ldtWakeUp    the wakeup timestamp in milliseconds (using
         *                     Container.currentTimeMillis())
         * @param fKeepAlive   if true, the alarm needs to be registered with the container
         */
        protected Alarm(WeakCallback refCallback, long ldtWakeUp, boolean fKeepAlive) {
            f_refCallback = refCallback;
            f_ldtWakeup   = ldtWakeUp;
            m_trigger     = new Trigger(this);
            f_Registered  = fKeepAlive;

            if (fKeepAlive) {
                refCallback.get().f_container.registerNativeCallback();
            }
        }

        /**
         * @return the current trigger
         */
        public Trigger getTrigger() {
            return m_trigger;
        }

        /**
         * Called when the alarm is triggered by the Java timer.
         */
        public void run() {
            ServiceContext context = f_refCallback.get();
            if (context != null) {
                Container container = context.f_container;
                if (container.isTimeFrozen()) {
                    // if the time is currently frozen, we have no way of knowing when it's going to
                    // be ready (how long will someone be looking at the debugger screen); so
                    // re-checking in a second seems like a reasonable compromise
                    TIMER.schedule(m_trigger = new Trigger(this), 1000);
                    return;
                }

                long ldtNow = container.currentTimeMillis();
                if (ldtNow >= f_ldtWakeup) {
                    WeakCallback.Callback callback = f_refCallback.extractCallback();
                    context.callLater(callback.frame(), callback.functionHandle(), Utils.OBJECTS_NONE);
                    if (f_Registered) {
                        container.unregisterNativeCallback();
                    }
                } else {
                    // reschedule
                    TIMER.schedule(m_trigger = new Trigger(this), f_ldtWakeup - ldtNow);
                }
            }
        }

        /**
         * Called when the alarm is canceled by the natural code.
         */
        public boolean cancel() {
            boolean        fCancelled = m_trigger.cancel();
            ServiceContext context    = f_refCallback.get();
            if (context != null && fCancelled && f_Registered) {
                context.f_container.unregisterNativeCallback();
            }
            return fCancelled;
        }

        /**
         * A TimerTask that is scheduled on the Java timer and is used to trigger the alarm.
         */
        protected static class Trigger
                extends TimerTask {
            protected Trigger(Alarm alarm) {
                f_alarm = alarm;
            }

            @Override
            public void run() {
                f_alarm.run();
            }

            private final Alarm f_alarm;
        }

        private final WeakCallback f_refCallback;
        private final long         f_ldtWakeup;
        private final boolean      f_Registered;
        private       Trigger      m_trigger;
    }


    // ----- constants and fields ------------------------------------------------------------------

    public static Timer TIMER = new Timer("ecstasy:LocalClock", true);

    /**
     * Cached Time class.
     */
    private TypeComposition m_clzTime;

    /**
     * Cached TimeZone handle.
     */
    private GenericHandle m_hTimeZone;

    /**
     * Cached LocalClock handle.
     */
    private ObjectHandle m_hLocalClock;
}