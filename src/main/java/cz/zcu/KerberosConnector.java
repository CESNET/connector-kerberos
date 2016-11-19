/*
 * DO NOT REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2016 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://opensource.org/licenses/CDDL-1.0
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://opensource.org/licenses/CDDL-1.0
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 */

package cz.zcu;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.logging.Log;
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
public class KerberosConnector implements Connector, CreateOp, DeleteOp, SearchOp<String>, TestOp, UpdateOp, SchemaOp {

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
	private native void krb5_renew();

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
		if (ObjectClass.ACCOUNT.equals(objectClass) || ObjectClass.GROUP.equals(objectClass)) {
			Name name = AttributeUtil.getNameFromAttributes(createAttributes);
			if (name != null) {
				// do real create here
				return new Uid(AttributeUtil.getStringValue(name).toLowerCase(Locale.US));
			} else {
				throw new InvalidAttributeValueException("Name attribute is required");
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
		if (ObjectClass.ACCOUNT.equals(objectClass) || ObjectClass.GROUP.equals(objectClass)) {
			// do real delete here
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
	public void executeQuery(ObjectClass objectClass, String query, ResultsHandler handler,
	                         OperationOptions options) {
		final ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid("3f50eca0-f5e9-11e3-a3ac-0800200c9a66");
		builder.setName("Foo");
		builder.addAttribute(AttributeBuilder.buildEnabled(true));

		for (ConnectorObject connectorObject : CollectionUtil.newSet(builder.build())) {
			if (!handler.handle(connectorObject)) {
				// Stop iterating because the handler stopped processing
				break;
			}
		}
		if (options.getPageSize() != null && 0 < options.getPageSize()) {
			logger.info("Paged Search was requested");
			((SearchResultsHandler) handler).handleResult(new SearchResult("0", 0));
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void test() {
		logger.ok("Test works well");
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

		} else if (ObjectClass.GROUP.is(objectClass.getObjectClassValue())) {
			if (attributesAccessor.hasAttribute("members")) {
				throw new InvalidAttributeValueException(
						"Requested to update a read only attribute");
			}
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
