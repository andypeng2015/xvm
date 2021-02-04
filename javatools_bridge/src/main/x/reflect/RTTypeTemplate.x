import ecstasy.reflect.Access;
import ecstasy.reflect.AnnotationTemplate;
import ecstasy.reflect.ClassTemplate.Composition;
import ecstasy.reflect.PropertyTemplate;
import ecstasy.reflect.TypeTemplate;


/**
 * The native reflected TypeTemplate implementation.
 */
const RTTypeTemplate
        implements TypeTemplate
    {
    @Override @RO String         desc;
    @Override @RO Boolean        explicitlyImmutable;
    @Override @RO Form           form;
    @Override @RO String?        name;
    @Override @RO Boolean        recursive;
    @Override @RO TypeTemplate[] underlyingTypes;

    @Override conditional Access accessSpecified();
    @Override conditional AnnotationTemplate annotated();
    @Override conditional TypeTemplate contained();
    @Override conditional Composition fromClass();
    @Override conditional Composition fromProperty();
    @Override Boolean isA(TypeTemplate that);
    @Override conditional TypeTemplate modifying();
    @Override conditional TypeTemplate[] parameterized();
    @Override TypeTemplate purify();
    @Override conditional (TypeTemplate, TypeTemplate) relational();

    // natural:
    //   toString()
    //   estimateStringLength()
    //   appendTo(buf)
    }
