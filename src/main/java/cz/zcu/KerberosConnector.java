package cz.zcu;

import java.util.*;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.*;

/**
 * Main implementation of the Kerberos Connector.
 */
@ConnectorClass(
		displayNameKey = "Kerberos.connector.display",
		configurationClass = KerberosConfiguration.class)
public class KerberosConnector implements Connector, CreateOp, DeleteOp, SearchOp<String>, UpdateOp, SchemaOp {

	/**
	 * Setup logging for the {@link KerberosConnector}.
	 */
	private static final Log logger = Log.getLog(KerberosConnector.class);

	/**
	 * Place holder for the {@link Configuration} passed into the init() method
	 * {@link KerberosConnector#init(org.identityconnectors.framework.spi.Configuration)}.
	 */
	private KerberosConfiguration configuration;

	private Schema schema = null;

	private long contextPointer;

	public long getContextPointer() {
		return this.contextPointer;
	}

	/**
	 * Gets the Configuration context for this connector.
	 *
	 * @return The current {@link Configuration}
	 */
	public Configuration getConfiguration() {
		return this.configuration;
	}

	/**
	 * Callback method to receive the {@link Configuration}.
	 *
	 * @param configuration the new {@link Configuration}
	 * @see org.identityconnectors.framework.spi.Connector#init(org.identityconnectors.framework.spi.Configuration)
	 */
	public void init(final Configuration configuration) {
		this.configuration = (KerberosConfiguration) configuration;
		krb5_init(GuardedStringAccessor.class);
	}

	/**
	 * Disposes of the {@link KerberosConnector}'s resources.
	 *
	 * @see org.identityconnectors.framework.spi.Connector#dispose()
	 */
	public void dispose() {
		krb5_destroy();
		configuration = null;
	}

	private native void krb5_init(Class gsAccessor);
	private native void krb5_destroy();
	private native void krb5_renew(Class gsAccessor);
	private native void krb5_create(String name, String password, long principalExpiry, long passwordExpiry, int attributes, String policy);
	private native void krb5_delete(String name);
	private native KerberosSearchResults krb5_search(String query, int pageSize, int pageOffset);

	/******************
	 * SPI Operations
	 *
	 * Implement the following operations using the contract and
	 * description found in the Javadoc for these methods.
	 ******************/

	/**
	 * {@inheritDoc}
	 */
	public Uid create(final ObjectClass objectClass, final Set<Attribute> createAttributes,
	                  final OperationOptions options) {
		if (ObjectClass.ACCOUNT.equals(objectClass)) {
			Name name = AttributeUtil.getNameFromAttributes(createAttributes);
			GuardedString password = AttributeUtil.getPasswordValue(createAttributes);
			long principalExpiry = AttributeUtil.getLongValue(AttributeUtil.find(OperationalAttributes.DISABLE_DATE_NAME, createAttributes));
			long passwordExpiry = AttributeUtil.getLongValue(AttributeUtil.find(OperationalAttributes.PASSWORD_EXPIRATION_DATE_NAME, createAttributes));
			int attributes = AttributeUtil.getIntegerValue(AttributeUtil.find("attributes", createAttributes));
			String policy = AttributeUtil.getStringValue(AttributeUtil.find("policy", createAttributes));

			if (name != null && password != null) {
				krb5_create(name.getNameValue(), GuardedStringAccessor.getString(password), principalExpiry, passwordExpiry,
						attributes, policy);
				return new Uid(AttributeUtil.getStringValue(name).toLowerCase());
			} else {
				throw new InvalidAttributeValueException("Name and password attributes are required");
			}
		} else {
			logger.warn("Create of type {0} is not supported", configuration.getConnectorMessages()
					.format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Create of type"
					+ objectClass.getObjectClassValue() + " is not supported");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void delete(final ObjectClass objectClass, final Uid uid, final OperationOptions options) {
		if (ObjectClass.ACCOUNT.equals(objectClass)) {
			krb5_delete(uid.getUidValue());
		} else {
			logger.warn("Delete of type {0} is not supported", configuration.getConnectorMessages()
					.format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Delete of type"
					+ objectClass.getObjectClassValue() + " is not supported");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public FilterTranslator<String> createFilterTranslator(ObjectClass objectClass,
	                                                       OperationOptions options) {
		return new KerberosFilterTranslator();
	}

	/**
	 * {@inheritDoc}
	 */
	public void executeQuery(ObjectClass objectClass, String query, ResultsHandler handler, OperationOptions options) {
		if (options.getPageSize() != null && 0 < options.getPageSize()) {
			logger.info("Paged search was requested...: " + options.getPagedResultsOffset());

			KerberosSearchResults results = krb5_search(query, options.getPageSize(), options.getPagedResultsOffset());
			for (KerberosPrincipal principal : results.principals) {
				if (!handler.handle(principal.toConnectorObject())) {
					//Stop iterating because the handler stopped processing
					((SearchResultsHandler)handler).handleResult(new SearchResult("NO_COOKIE", results.remaining));
					break;
				}
			}
		} else {
			logger.info("Full search was requested...");
			KerberosSearchResults results = krb5_search(query, 0, 0);
			for (KerberosPrincipal principal : results.principals) {
				if (!handler.handle(principal.toConnectorObject())) {
					//Stop iterating because the handler stopped processing
					break;
				}
			}
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes,
	                  OperationOptions options) {
		AttributesAccessor attributesAccessor = new AttributesAccessor(replaceAttributes);
		Name newName = attributesAccessor.getName();
		Uid uidAfterUpdate = uid;
		if (newName != null) {
			logger.info("Rename the object {0}:{1} to {2}", objectClass.getObjectClassValue(), uid
					.getUidValue(), newName.getNameValue());
			uidAfterUpdate = new Uid(newName.getNameValue().toLowerCase(Locale.US));
		}

		if (ObjectClass.ACCOUNT.equals(objectClass)) {

		} else {
			logger.warn("Update of type {0} is not supported", configuration.getConnectorMessages()
					.format(objectClass.getDisplayNameKey(), objectClass.getObjectClassValue()));
			throw new UnsupportedOperationException("Update of type"
					+ objectClass.getObjectClassValue() + " is not supported");
		}
		return uidAfterUpdate;
	}


	public Schema schema() {
		logger.info("schema()");
		if (schema == null) {
			schema = buildSchema();
		}
		return schema;
	}


	private Schema buildSchema() {
		final SchemaBuilder schemaBuilder = new SchemaBuilder(KerberosConnector.class);
		Set<AttributeInfo> attributes = new HashSet<AttributeInfo>();

		attributes.add(OperationalAttributeInfos.DISABLE_DATE);
		attributes.add(OperationalAttributeInfos.ENABLE);
		attributes.add(OperationalAttributeInfos.PASSWORD);
		attributes.add(OperationalAttributeInfos.PASSWORD_EXPIRATION_DATE);

		attributes.add(AttributeInfoBuilder.build("passwordChangeDate",
			long.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("modifyPrincipal",
			String.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("modifyDate",
			long.class, EnumSet.of(Flags.NOT_UPDATEABLE)));

		attributes.add(AttributeInfoBuilder.build("attributes", int.class));
		attributes.add(AttributeInfoBuilder.build("policy", String.class));

		final ObjectClassInfo ociInfoAccount = new ObjectClassInfoBuilder().setType(ObjectClass.ACCOUNT_NAME).addAllAttributeInfo(attributes).build();
		schemaBuilder.defineObjectClass(ociInfoAccount);

		return schemaBuilder.build();
	}

	static {
		System.loadLibrary("kerberos-connector");
	}
}
