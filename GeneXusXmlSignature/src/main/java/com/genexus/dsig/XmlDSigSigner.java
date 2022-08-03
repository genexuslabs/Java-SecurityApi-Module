package com.genexus.dsig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.transforms.params.XPathContainer;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.genexus.commons.DSigOptions;
import com.genexus.config.Config;
import com.genexus.securityapicommons.commons.Certificate;
import com.genexus.securityapicommons.commons.SecurityAPIObject;
import com.genexus.securityapicommons.keys.CertificateX509;
import com.genexus.securityapicommons.keys.PrivateKeyManager;
import com.genexus.securityapicommons.utils.SecurityUtils;
import com.genexus.utils.CanonicalizerWrapper;
import com.genexus.utils.KeyInfoType;
import com.genexus.utils.MessageDigestAlgorithmWrapper;
import com.genexus.utils.SignatureElementType;
import com.genexus.utils.SignatureUtils;
import com.genexus.utils.TransformsWrapper;
import com.genexus.utils.XMLSignatureWrapper;

public class XmlDSigSigner extends SecurityAPIObject {

	private PublicKey publicKey;
	private PrivateKey privateKey;
	private String digest;
	private String asymAlgorithm;

	public XmlDSigSigner() {
		super();
		if (Config.getUseLineBreaks()) {
			org.apache.xml.security.Init.init();
		} else {
			/*** CONDITIONAL ***/
			/** https://issues.apache.org/jira/browse/SANTUARIO-482 **/
			System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
			org.apache.xml.security.Init.init();
		}

	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/

	public boolean doSignFile(String xmlFilePath, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, String outputPath, DSigOptions options) {
		return Boolean.valueOf(axuiliarSign(xmlFilePath, key, certificate, outputPath, options, true, ""));
	}

	public String doSign(String xmlInput, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, DSigOptions options) {
		return axuiliarSign(xmlInput, key, certificate, "", options, false, "");
	}

	public boolean doSignFileElement(String xmlFilePath, String xPath,
			com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate, String outputPath,
			DSigOptions options) {
		return Boolean.valueOf(axuiliarSign(xmlFilePath, key, certificate, outputPath, options, true, xPath));
	}

	public String doSignElement(String xmlInput, String xPath, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, DSigOptions options) {
		return axuiliarSign(xmlInput, key, certificate, "", options, false, xPath);
	}

	public boolean doVerify(String xmlSigned, DSigOptions options) {
		return auxiliarVerify(xmlSigned, options, false, false, null);
	}

	public boolean doVerifyFile(String xmlFilePath, DSigOptions options) {
		return auxiliarVerify(xmlFilePath, options, true, false, null);
	}

	public boolean doVerifyWithCert(String xmlSigned, Certificate certificate, DSigOptions options) {
		return auxiliarVerify(xmlSigned, options, false, true, certificate);
	}

	public boolean doVerifyFileWithCert(String xmlFilePath, Certificate certificate, DSigOptions options) {
		return auxiliarVerify(xmlFilePath, options, true, true, certificate);
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private String axuiliarSign(String xmlInput, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, String outputPath, DSigOptions options, boolean isFile, String xPath) {
		if (TransformsWrapper.getTransformsWrapper(options.getDSigSignatureType(),
				this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("XD001", "Not implemented DSigType");
		}
		CertificateX509 cert = (CertificateX509) certificate;
		if (!cert.Inicialized()) {
			this.error.setError("XD002", "Certificate not loaded");
		}

		Document xmlDoc = loadDocument(isFile, xmlInput, options);
		if (this.hasError()) {
			return "";
		}
		String result = Sign(xmlDoc, (PrivateKeyManager) key, cert, options.getDSigSignatureType(),
				options.getCanonicalization(), options.getKeyInfoType(), xPath, options.getIdentifierAttribute());
		if (isFile) {
			String prefix = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
			result = Boolean.toString(SignatureUtils.writeToFile(result, outputPath, prefix, this.error));
		}
		return result;
	}

	private String Sign(Document xmlInput, PrivateKeyManager key, CertificateX509 certificate, String dSigType,
			String canonicalizationType, String keyInfoType, String xpath, String id) {
		SignatureElementType signatureElementType;
		if (!SecurityUtils.compareStrings(xpath, "")) {
			if (xpath.charAt(0) == '#') {
				signatureElementType = SignatureElementType.id;
				if (id == null || SecurityUtils.compareStrings(id, "")) {
					this.error.setError("XD003", "Identifier attribute name missing");
					return "";
				}
			} else {
				signatureElementType = SignatureElementType.path;
			}
		} else {
			signatureElementType = SignatureElementType.document;
		}
		boolean inicialized = inicializeInstanceVariables(key, certificate);
		if (!inicialized) {
			return "";
		}
		Element rootElement = SignatureUtils.getRootElement(xmlInput);

		CanonicalizerWrapper canonicalizerWrapper = CanonicalizerWrapper.getCanonicalizerWrapper(canonicalizationType,
				this.error);
		String canonicalizationMethodAlgorithm = CanonicalizerWrapper
				.getCanonicalizationMethodAlorithm(canonicalizerWrapper, error);
		XMLSignatureWrapper xMLSignatureWrapper = XMLSignatureWrapper
				.getXMLSignatureWrapper(this.asymAlgorithm + "_" + this.digest, this.error);
		TransformsWrapper transformsWrapper = TransformsWrapper.getTransformsWrapper(dSigType, this.error);
		String signatureTypeTransform = TransformsWrapper.getSignatureTypeTransform(transformsWrapper, this.error);
		MessageDigestAlgorithmWrapper messageDigestAlgorithmWrapper = MessageDigestAlgorithmWrapper
				.getMessageDigestAlgorithmWrapper(this.digest, this.error);
		if (this.hasError()) {
			return "";
		}

		Element canonElem = XMLUtils.createElementInSignatureSpace(xmlInput, Constants._TAG_CANONICALIZATIONMETHOD);
		canonElem.setAttributeNS(null, Constants._ATT_ALGORITHM, canonicalizationMethodAlgorithm);
		SignatureAlgorithm signatureAlgorithm = null;
		XMLSignature sig = null;
		try {
			signatureAlgorithm = new SignatureAlgorithm(xmlInput,
					XMLSignatureWrapper.getSignatureMethodAlgorithm(xMLSignatureWrapper, this.error));
			if (this.hasError()) {
				return "";
			}
			sig = new XMLSignature(xmlInput, null, signatureAlgorithm.getElement(), canonElem);
		} catch (Exception e) {
			this.error.setError("XD004", e.getMessage());
			return null;
		}

		Transforms transforms = new Transforms(xmlInput);
		String referenceURI = "";
		try {
			transforms.addTransform(signatureTypeTransform);
			transforms.addTransform(canonicalizationMethodAlgorithm);
			switch (signatureElementType) {
			case path:
				Node xpathNode = (Node) SignatureUtils.getNodeFromPath(xmlInput, xpath, this.error);
				if (this.hasError() || xpathNode == null) {
					return "";
				}
				Node parentNode = (Node) xpathNode.getParentNode();
				parentNode.appendChild(sig.getElement());
				XPathContainer xpathC = new XPathContainer(xmlInput);
				xpathC.setXPath(xpath);
				transforms.addTransform(Transforms.TRANSFORM_XPATH, xpathC.getElementPlusReturns());

				// transforms.addTransform(Transform.XPATH);
				break;
			case id:
				Node idNode = (Node) SignatureUtils.getNodeFromID(xmlInput, id, xpath, this.error);
				if (this.hasError()) {
					return "";
				}
				Element idElement = (Element) idNode;
				idElement.setIdAttribute(id, true);

				referenceURI = xpath;
				// rootElement.appendChild(sig.getElement());
				Node parentNodeID = (Node) idNode.getParentNode();
				parentNodeID.appendChild(sig.getElement());
				break;
			default:
				rootElement.appendChild(sig.getElement());
				break;
			}
			sig.addDocument(referenceURI, transforms,
					MessageDigestAlgorithmWrapper.getDigestMethod(messageDigestAlgorithmWrapper, this.error));
		} catch (Exception e) {
			this.error.setError("XD005", e.getMessage());
			return "";
		}
		KeyInfoType kyInfo = KeyInfoType.getKeyInfoType(keyInfoType, this.error);
		if (this.hasError()) {
			return "";
		}
		switch (kyInfo) {

		case X509Certificate:

			try {
				X509Certificate x509Certificate = certificate.Cert();
				X509Data x509data = new X509Data(sig.getDocument());
				x509data.addIssuerSerial(x509Certificate.getIssuerDN().getName(), x509Certificate.getSerialNumber());
				x509data.addSubjectName(x509Certificate);
				x509data.addCertificate(x509Certificate);
				sig.getKeyInfo().add(x509data);
			} catch (Exception e) {
				this.error.setError("XD006", e.getMessage());
			}
			break;
		case KeyValue:
			sig.addKeyInfo(this.publicKey);
			break;
		case NONE:
			break;
		default:
			this.error.setError("XD007", "Undefined KeyInfo type");
			return "";
		}
		try {
			sig.sign(this.privateKey);
		} catch (Exception e) {
			error.setError("XD008", e.getMessage());
			e.printStackTrace();

			return null;
		}
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		XMLUtils.outputDOMc14nWithComments(xmlInput, bos);

		return new String(bos.toByteArray());
	}

	private boolean inicializeInstanceVariables(PrivateKeyManager key, CertificateX509 certificate) {

		this.privateKey = key.getPrivateKeyXML();
		this.publicKey = certificate.getPublicKeyXML();
		this.digest = certificate.getPublicKeyHash();
		this.asymAlgorithm = certificate.getPublicKeyAlgorithm();
		return true;
	}

	private boolean auxiliarVerify(String input, DSigOptions options, boolean isFile, boolean withCert,
			Certificate certificate) {
		if (TransformsWrapper.getTransformsWrapper(options.getDSigSignatureType(),
				this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("XD001", "Not implemented DSigType");
		}
		Document doc = loadDocument(isFile, input, options);
		if (this.hasError()) {
			return false;
		}
		String baseURI = "";
		if (isFile) {

			try {
				File f = new File(input);
				baseURI = f.toURI().toURL().toString();
			} catch (Exception e) {
				this.error.setError("XD009", e.getMessage());
				return false;
			}
		}
		return verify(doc, baseURI, options.getIdentifierAttribute(), withCert, (CertificateX509) certificate);
	}

	private boolean verify(Document doc, String baseURI, String id, boolean withCert, CertificateX509 certificate) {
		Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
				.item(0);
		if (id != null && !SecurityUtils.compareStrings(id, "")) {
			// Element ref = (Element) doc.getElementsByTagName(Constants._TAG_REFERENCE);
			Element ref = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_REFERENCE)
					.item(0);
			String sigId = ref.getAttribute(Constants._ATT_URI);
			if (sigId == null || SecurityUtils.compareStrings(sigId, "")) {
				this.error.setError("XD010", "Could not find Reference URI for id");
				return false;
			}
			Element idElement = (Element) SignatureUtils.getNodeFromID(doc, id, sigId, this.error);
			if (idElement == null) {
				this.error.setError("XD011", "Could not find node from ID");
				return false;
			}
			idElement.setIdAttribute(id, true);
		}

		boolean result = false;
		try {

			XMLSignature signature = new XMLSignature(sigElement, baseURI);
			if (withCert) {
				PublicKey pk = certificate.getPublicKeyXML();
				result = signature.checkSignatureValue(pk);
			} else {
				result = signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
			}
		} catch (Exception e) {

			this.error.setError("XD012", e.getMessage());
			return false;
		}
		return result;
	}

	private Document loadDocument(boolean isFile, String path, DSigOptions options) {
		Document xmlDoc = null;
		if (isFile) {
			if (!SignatureUtils.validateExtensionXML(path)) {
				this.error.setError("XD013", "Not XML file");
				return null;
			}
			xmlDoc = SignatureUtils.documentFromFile(path, options.getXmlSchemaPath(), this.error);

		} else {
			xmlDoc = SignatureUtils.documentFromString(path, options.getXmlSchemaPath(), this.error);
		}
		return xmlDoc;
	}

}
