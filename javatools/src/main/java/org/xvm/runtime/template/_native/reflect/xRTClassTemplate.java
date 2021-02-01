package org.xvm.runtime.template._native.reflect;


import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.xvm.asm.ClassStructure;
import org.xvm.asm.Component;
import org.xvm.asm.Component.Contribution;
import org.xvm.asm.ConstantPool;
import org.xvm.asm.MethodStructure;
import org.xvm.asm.ModuleStructure;
import org.xvm.asm.Op;
import org.xvm.asm.PackageStructure;
import org.xvm.asm.PropertyStructure;

import org.xvm.asm.constants.ClassConstant;
import org.xvm.asm.constants.IdentityConstant;
import org.xvm.asm.constants.StringConstant;
import org.xvm.asm.constants.TypeConstant;

import org.xvm.runtime.Frame;
import org.xvm.runtime.ObjectHandle;
import org.xvm.runtime.ObjectHandle.ArrayHandle;
import org.xvm.runtime.ObjectHandle.GenericHandle;
import org.xvm.runtime.TemplateRegistry;
import org.xvm.runtime.TypeComposition;
import org.xvm.runtime.Utils;

import org.xvm.runtime.template.xBoolean;
import org.xvm.runtime.template.xEnum;
import org.xvm.runtime.template.xException;
import org.xvm.runtime.template.xNullable;

import org.xvm.runtime.template.collections.xArray;

import org.xvm.runtime.template.text.xString;
import org.xvm.runtime.template.text.xString.StringHandle;

import org.xvm.runtime.template._native.reflect.xRTType.TypeHandle;


/**
 * Native RTClassTemplate implementation.
 */
public class xRTClassTemplate
        extends xRTComponentTemplate
    {
    public static xRTClassTemplate INSTANCE;

    public xRTClassTemplate(TemplateRegistry templates, ClassStructure structure, boolean fInstance)
        {
        super(templates, structure, false);

        if (fInstance)
            {
            INSTANCE = this;
            }
        }

    @Override
    public void initNative()
        {
        if (this == INSTANCE)
            {
            ConstantPool     pool     = pool();
            TemplateRegistry registry = f_templates;

            TypeConstant typeClassTemplate = pool.ensureEcstasyTypeConstant("reflect.ClassTemplate");

            CLASS_TEMPLATE_COMP = ensureClass(getCanonicalType(), typeClassTemplate);
            CONTRIBUTION_COMP   = registry.resolveClass(
                pool.ensureEcstasyTypeConstant("reflect.ClassTemplate.Composition.Contribution"));

            ACTION = (xEnum) registry.getTemplate("reflect.ClassTemplate.Composition.Action");

            CREATE_CONTRIB_METHOD = getStructure().findMethod("createContribution", 5);

            markNativeProperty("implicitName");
            markNativeProperty("classes");
            markNativeProperty("contribs");
            markNativeProperty("mixesInto");
            markNativeProperty("multimethods");
            markNativeProperty("properties");
            markNativeProperty("singleton");
            markNativeProperty("sourceInfo");
            markNativeProperty("type");
            markNativeProperty("typeParams");
            markNativeProperty("virtualChild");

            markNativeMethod("deannotate", null, null);
            markNativeMethod("ensureClass", null, null);

            // this native implementation explicitly incorporates the native implementation of
            // RTComponentTemplate
            super.initNative();
            }
        }

    @Override
    public int invokeNativeGet(Frame frame, String sPropName, ObjectHandle hTarget, int iReturn)
        {
        ComponentTemplateHandle hComponent = (ComponentTemplateHandle) hTarget;
        switch (sPropName)
            {
            case "implicitName":
                return getPropertyImplicitName(frame, hComponent, iReturn);

            case "classes":
                return getPropertyClasses(frame, hComponent, iReturn);

            case "contribs":
                return getPropertyContribs(frame, hComponent, iReturn);

            case "mixesInto":
                return getPropertyMixesInto(frame, hComponent, iReturn);

            case "multimethods":
                return getPropertyMultimethods(frame, hComponent, iReturn);

            case "properties":
                return getPropertyProperties(frame, hComponent, iReturn);

            case "singleton":
                return getPropertySingleton(frame, hComponent, iReturn);

            case "sourceInfo":
                return getPropertySourceInfo(frame, hComponent, iReturn);

            case "type":
                return getPropertyType(frame, hComponent, iReturn);

            case "typeParams":
                return getPropertyTypeParams(frame, hComponent, iReturn);

            case "virtualChild":
                return getPropertyVirtualChild(frame, hComponent, iReturn);
            }

        return super.invokeNativeGet(frame, sPropName, hTarget, iReturn);
        }

    @Override
    public int invokeNative1(Frame frame, MethodStructure method, ObjectHandle hTarget,
                             ObjectHandle hArg, int iReturn)
        {
        ComponentTemplateHandle hComponent = (ComponentTemplateHandle) hTarget;
        switch (method.getName())
            {
            case "ensureClass":
                return invokeEnsureClass(frame, hComponent, iReturn);
            }

        return super.invokeNative1(frame, method, hTarget, hArg, iReturn);
        }

    @Override
    public int invokeNativeNN(Frame frame, MethodStructure method, ObjectHandle hTarget,
                              ObjectHandle[] ahArg, int[] aiReturn)
        {
        ComponentTemplateHandle hComponent = (ComponentTemplateHandle) hTarget;
        switch (method.getName())
            {
            case "deannotate":
                return invokeDeannotate(frame, hComponent, aiReturn);
            }

        return super.invokeNativeNN(frame, method, hTarget, ahArg, aiReturn);
        }


    // ----- property implementations --------------------------------------------------------------

    /**
     * Implements property: implicitName.get()
     */
    public int getPropertyImplicitName(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure   clz   = (ClassStructure) hComponent.getComponent();
        IdentityConstant idClz = clz.getIdentityConstant();
        if (idClz instanceof ClassConstant)
            {
            String sAlias = ((ClassConstant) idClz).getImplicitImportName();
            if (sAlias != null)
                {
                return frame.assignValue(iReturn, xString.makeHandle(sAlias));
                }
            }
        return frame.assignValue(iReturn, xNullable.NULL);
        }

    /**
     * Implements property: classes.get()
     */
    public int getPropertyClasses(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz = (ClassStructure) hComponent.getComponent();
        if (!clz.getFileStructure().isLinked())
            {
            return frame.raiseException(xException.illegalState(frame, "FileTemplate is not resolved"));
            }

        List<ComponentTemplateHandle> listTemplates = new ArrayList<>();
        for (Component child : clz.children())
            {
            switch (child.getFormat())
                {
                case INTERFACE:
                case CLASS:
                case CONST:
                case ENUM:
                case ENUMVALUE:
                case MIXIN:
                case SERVICE:
                    listTemplates.add(xRTClassTemplate.makeHandle((ClassStructure) child));
                    break;

                case PACKAGE:
                    listTemplates.add(xRTPackageTemplate.makeHandle((PackageStructure) child));
                    break;

                case MODULE:
                    listTemplates.add(xRTModuleTemplate.makeHandle((ModuleStructure) child));
                    break;
                }
            }

        ArrayHandle hArray = xArray.INSTANCE.createArrayHandle(
                ensureClassTemplateArrayComposition(),
                listTemplates.toArray(new ComponentTemplateHandle[0]));
        return frame.assignValue(iReturn, hArray);
        }

    /**
     * Implements property: contribs.get()
     */
    public int getPropertyContribs(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz = (ClassStructure) hComponent.getComponent();
        if (!clz.getFileStructure().isLinked())
            {
            return frame.raiseException(xException.illegalState(frame, "FileTemplate is not resolved"));
            }

        List<Contribution>  listContrib = clz.getContributionsAsList();
        Utils.ValueSupplier supplier    = (frameCaller, index) ->
            {
            ConstantPool pool        = frameCaller.poolContext();
            Contribution contrib     = listContrib.get(index);
            TypeConstant typeContrib = contrib.getTypeConstant();
            ObjectHandle hDelegatee  = xNullable.NULL; // TODO
            ObjectHandle haNames     = xNullable.NULL;
            ObjectHandle haTypes     = xNullable.NULL;

            String sAction;
            switch (contrib.getComposition())
                {
                case Annotation:
                    sAction = "AnnotatedBy";
                    break;
                case Extends:
                    sAction = "Extends";
                    break;
                case Implements:
                    sAction = "Implements";
                    break;
                case Delegates:
                    sAction = "Delegates";
                    break;
                case Into:
                    sAction = "MixesInto";
                    break;
                case Incorporates:
                    {
                    Map<StringConstant, TypeConstant> mapConstraints = contrib.getTypeParams();
                    int cConstraints = mapConstraints == null ? 0 : mapConstraints.size();
                    if (cConstraints > 0)
                        {
                        StringHandle[] ahNames = new StringHandle[cConstraints];
                        TypeHandle[]   ahTypes = new TypeHandle[cConstraints];
                        int            i = 0;
                        for (Map.Entry<StringConstant, TypeConstant> entry : mapConstraints.entrySet())
                            {
                            String       sName = entry.getKey().getValue();
                            TypeConstant type  = entry.getValue();

                            ahNames[i] = xString.makeHandle(sName);
                            ahTypes[i] = type.ensureTypeHandle(pool);
                            i++;
                            }
                        haNames = xArray.makeStringArrayHandle(ahNames);
                        haTypes = xArray.INSTANCE.createArrayHandle(
                                    xRTType.ensureTypeArrayComposition(), ahTypes);
                        }
                    sAction = "Incorporates";
                    break;
                    }
                default:
                    throw new IllegalStateException();
                }

            ObjectHandle[] ahVar = new ObjectHandle[CREATE_CONTRIB_METHOD.getMaxVars()];
            ahVar[0] = Utils.ensureInitializedEnum(frameCaller, ACTION.getEnumByName(sAction));
            ahVar[1] = typeContrib.ensureTypeHandle(pool);
            ahVar[2] = hDelegatee;
            ahVar[3] = haNames;
            ahVar[3] = haTypes;

            return frameCaller.call1(CREATE_CONTRIB_METHOD, null, ahVar, Op.A_STACK);
            };

        return xArray.createAndFill(frame, ensureContribArrayComposition(),
                listContrib.size(), supplier, iReturn);
        }

    /**
     * Implements property: mixesInto.get()
     */
    public int getPropertyMixesInto(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz       = (ClassStructure) hComponent.getComponent();
        GenericHandle  hTemplate = null; // TODO
        return frame.assignValue(iReturn, hTemplate);
        }

    /**
     * Implements property: multimethods.get()
     */
    public int getPropertyMultimethods(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz    = (ClassStructure) hComponent.getComponent();
        GenericHandle  hArray = null; // TODO
        return frame.assignValue(iReturn, hArray);
        }

    /**
     * Implements property: properties.get()
     */
    public int getPropertyProperties(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz = (ClassStructure) hComponent.getComponent();
        if (!clz.getFileStructure().isLinked())
            {
            return frame.raiseException(xException.illegalState(frame, "FileTemplate is not resolved"));
            }

        List<ComponentTemplateHandle> listProps = new ArrayList<>();
        for (Component child : clz.children())
            {
            if (child instanceof PropertyStructure)
                {
                listProps.add(xRTPropertyTemplate.makePropertyHandle((PropertyStructure) child));
                }
            }

        ComponentTemplateHandle[] ahProp = listProps.toArray(new ComponentTemplateHandle[0]);
        ArrayHandle hArray = xArray.INSTANCE.createArrayHandle(
                xRTPropertyTemplate.ensureArrayComposition(), ahProp);
        return frame.assignValue(iReturn, hArray);
        }

    /**
     * Implements property: singleton.get()
     */
    public int getPropertySingleton(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz        = (ClassStructure) hComponent.getComponent();
        boolean        fSingleton = clz.isSingleton();
        return frame.assignValue(iReturn, xBoolean.makeHandle(fSingleton));
        }

    /**
     * Implements property: sourceInfo.get()
     */
    public int getPropertySourceInfo(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz   = (ClassStructure) hComponent.getComponent();
        GenericHandle  hInfo = null; // TODO
        return frame.assignValue(iReturn, hInfo);
        }

    /**
     * Implements property: type.get()
     */
    public int getPropertyType(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz = (ClassStructure) hComponent.getComponent();
        if (!clz.getFileStructure().isLinked())
            {
            return frame.raiseException(xException.illegalState(frame, "FileTemplate is not resolved"));
            }
        TypeConstant type = clz.getIdentityConstant().getType();
        return frame.assignValue(iReturn, xRTTypeTemplate.makeHandle(type));
        }

    /**
     * Implements property: typeParams.get()
     */
    public int getPropertyTypeParams(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz    = (ClassStructure) hComponent.getComponent();
        GenericHandle  hArray = null; // TODO
        return frame.assignValue(iReturn, hArray);
        }

    /**
     * Implements property: virtualChild.get()
     */
    public int getPropertyVirtualChild(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz      = (ClassStructure) hComponent.getComponent();
        boolean        fVirtual = clz.isVirtualChild();
        return frame.assignValue(iReturn, xBoolean.makeHandle(fVirtual));
        }


    // ----- method implementations ----------------------------------------------------------------

    /**
     * Implementation for: {@code Class<> ensureClass(Type... actualTypes)}.
     */
    protected int invokeEnsureClass(Frame frame, ComponentTemplateHandle hComponent, int iReturn)
        {
        ClassStructure clz = (ClassStructure) hComponent.getComponent();
        // TODO CP
        throw new UnsupportedOperationException();
        }

    /**
     * Implementation for: {@code conditional (Annotation, Composition) deannotate()}.
     */
    protected int invokeDeannotate(Frame frame, ComponentTemplateHandle hComponent, int[] aiReturn)
        {
        // a Composition that is a ClassTemplate is not annotated
        return frame.assignValue(aiReturn[0], xBoolean.FALSE);
        }


    // ----- ObjectHandle support ------------------------------------------------------------------

    /**
     * Obtain a {@link ComponentTemplateHandle} for the specified {@link ClassStructure}.
     *
     * @param structClz  the {@link ClassStructure} to obtain a {@link ComponentTemplateHandle} for
     *
     * @return the resulting {@link ComponentTemplateHandle}
     */
    public static ComponentTemplateHandle makeHandle(ClassStructure structClz)
        {
        // note: no need to initialize the struct because there are no natural fields
        return new ComponentTemplateHandle(CLASS_TEMPLATE_COMP, structClz);
        }

    /**
     * @return the ClassComposition for an Array of Contributions
     */
    public static TypeComposition ensureContribArrayComposition()
        {
        TypeComposition clz = CONTRIBUTION_ARRAY_COMP;
        if (clz == null)
            {
            ConstantPool pool = INSTANCE.pool();
            TypeConstant typeContribArray = pool.ensureParameterizedTypeConstant(pool.typeArray(),
                CONTRIBUTION_COMP.getType());
            CONTRIBUTION_ARRAY_COMP = clz = INSTANCE.f_templates.resolveClass(typeContribArray);
            assert clz != null;
            }
        return clz;
        }

    /**
     * @return the ClassComposition for an Array of ClassTemplates
     */
    public static TypeComposition ensureClassTemplateArrayComposition()
        {
        TypeComposition clz = CLASS_TEMPLATE_ARRAY_COMP;
        if (clz == null)
            {
            ConstantPool pool = INSTANCE.pool();
            TypeConstant typeClassTemplateArray = pool.ensureParameterizedTypeConstant(pool.typeArray(),
                CLASS_TEMPLATE_COMP.getType());
            CLASS_TEMPLATE_ARRAY_COMP = clz = INSTANCE.f_templates.resolveClass(typeClassTemplateArray);
            assert clz != null;
            }
        return clz;
        }


    // ----- constants -----------------------------------------------------------------------------

    private static TypeComposition CLASS_TEMPLATE_COMP;
    private static TypeComposition CONTRIBUTION_COMP;
    private static TypeComposition CONTRIBUTION_ARRAY_COMP;
    private static TypeComposition CLASS_TEMPLATE_ARRAY_COMP;

    public static xEnum           ACTION;
    public static MethodStructure CREATE_CONTRIB_METHOD;
    }
