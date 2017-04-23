package cz.zcu;

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.*;

/**
 * This is an implementation of AbstractFilterTranslator that gives a concrete representation
 * of which filters can be applied at the connector level (natively).
 * <p>
 * If the Kerberos doesn't support a certain expression type, that factory
 * method should return null. This level of filtering is present only to allow any
 * native constructs that may be available to help reduce the result set for the framework,
 * which will (strictly) reapply all filters specified after the connector does the initial
 * filtering.
 * <p>
 * Note: The generic query type is most commonly a String, but does not have to be.
 */
public class KerberosFilterTranslator extends AbstractFilterTranslator<String> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String createContainsExpression(ContainsFilter filter, boolean not) {
		if (filter.getAttribute().is(Name.NAME) ||
			filter.getAttribute().is(Uid.NAME)) {
			String value = AttributeUtil.getAsStringValue(filter.getAttribute());
			if (StringUtil.isBlank(value)) {
				return null;
			} else if (not) {
				//It's not possible to create a not filter
				return null;
			} else {
				return "*" + value + "*";
			}
		} else {
			//It's not possible to filter by different attributes
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String createEndsWithExpression(EndsWithFilter filter, boolean not) {
		if (filter.getAttribute().is(Name.NAME) ||
				filter.getAttribute().is(Uid.NAME)) {
			String value = AttributeUtil.getAsStringValue(filter.getAttribute());
			if (StringUtil.isBlank(value)) {
				return null;
			} else if (not) {
				//It's not possible to create a not filter
				return null;
			} else {
				return "*" + value;
			}
		} else {
			//It's not possible to filter by different attributes
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String createStartsWithExpression(StartsWithFilter filter, boolean not) {
		if (filter.getAttribute().is(Name.NAME) ||
				filter.getAttribute().is(Uid.NAME)) {
			String value = AttributeUtil.getAsStringValue(filter.getAttribute());
			if (StringUtil.isBlank(value)) {
				return null;
			} else if (not) {
				//It's not possible to create a not filter
				return null;
			} else {
				return value + "*";
			}
		} else {
			//It's not possible to filter by different attributes
			return null;
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String createEqualsExpression(EqualsFilter filter, boolean not) {
		if (filter.getAttribute().is(Name.NAME) ||
				filter.getAttribute().is(Uid.NAME)) {
			String value = AttributeUtil.getAsStringValue(filter.getAttribute());
			if (StringUtil.isBlank(value)) {
				return null;
			} else if (not) {
				//It's not possible to create a not filter
				return null;
			} else {
				return value;
			}
		} else {
			//It's not possible to filter by different attributes
			return null;
		}
	}
}
