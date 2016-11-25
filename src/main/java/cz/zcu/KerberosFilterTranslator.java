package cz.zcu;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;

/**
 * This is an implementation of AbstractFilterTranslator that gives a concrete representation
 * of which filters can be applied at the connector level (natively).
 * <p>
 * If the Kerberos doesn't support a certain expression type, that factory
 * method should return null. This level of filtering is present only to allow any
 * native constructs that may be available to help reduce the result set for the framework,
 * which will (strictly) reapply all filters specified after the connector does the initial
 * filtering.<p><p>Note: The generic query type is most commonly a String, but does not have to be.
 */
public class KerberosFilterTranslator extends AbstractFilterTranslator<String> {

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createContainsExpression(ContainsFilter filter, boolean not) {
        /*
         * Example implementation:
         * You may define the format of the queries for your connector, but
         * you must make sure that the executeQuery() (if you implemented Search)
         * method handles it appropriately.
         */
        String name = filter.getAttribute().getName();
        String value = AttributeUtil.getAsStringValue(filter.getAttribute());
        if (StringUtil.isBlank(value)) {
            return null;
        } else if (not) {
            //create an expression that means "not contains" or "doesn't contain" if possible
            return name + "!=*" + value + "*";
        } else {
            return name + "=*" + value + "*";
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createContainsAllValuesExpression(ContainsAllValuesFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createEndsWithExpression(EndsWithFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createStartsWithExpression(StartsWithFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createEqualsExpression(EqualsFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createAndExpression(String leftExpression, String rightExpression) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createOrExpression(String leftExpression, String rightExpression) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createGreaterThanExpression(GreaterThanFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createGreaterThanOrEqualExpression(GreaterThanOrEqualFilter filter,
                                                        boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createLessThanExpression(LessThanFilter filter, boolean not) {
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected String createLessThanOrEqualExpression(LessThanOrEqualFilter filter, boolean not) {
        return null;
    }
}
