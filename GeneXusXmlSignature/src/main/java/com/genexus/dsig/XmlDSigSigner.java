package com.genexus.dsig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.MalformedURLException;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
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

	public boolean doSignFile(String xmlFilePath, com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate, String outputPath,
			DSigOptions options) {
		this.error.cleanError();
		return doSignFilePKCS12(xmlFilePath, key, certificate, options.getDSigSignatureType(),
				options.getCanonicalization(), outputPath,
				options.getKeyInfoType(), options.getXmlSchemaPath());
	}

	public boolean doSignFileElement(String xmlFilePath, String xPath, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, String outputPath, DSigOptions options) {
		this.error.cleanError();
		return doSignFileElementPKCS12(xmlFilePath, xPath, key, certificate, options.getDSigSignatureType(),
				options.getCanonicalization(), outputPath,
				options.getKeyInfoType(), options.getXmlSchemaPath(), options.getIdentifierAttribute());
	}

	public String doSign(String xmlInput, com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate, DSigOptions options) {
		this.error.cleanError();
		return doSignPKCS12(xmlInput, key, certificate, options.getDSigSignatureType(),
				options.getCanonicalization(), options.getKeyInfoType(),
				options.getXmlSchemaPath());
	}

	public String doSignElement(String xmlInput, String xPath, com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate,
			DSigOptions options) {
		this.error.cleanError();
		return doSignElementPKCS12(xmlInput, xPath, key, certificate, options.getDSigSignatureType(),
				options.getCanonicalization(), options.getKeyInfoType(),
				options.getXmlSchemaPath(), options.getIdentifierAttribute());
	}

	public boolean doVerify(String xmlSigned, DSigOptions options) {
		this.error.cleanError();
		Document doc = SignatureUtils.documentFromString(xmlSigned, options.getXmlSchemaPath(), this.error);
		if (this.hasError()) {
			return false;
		}
		String baseURI = "";
		return verify(doc, baseURI, options.getIdentifierAttribute());
	}

	public boolean doVerifyFile(String xmlFilePath, DSigOptions options) {
		this.error.cleanError();
		if (!SignatureUtils.validateExtensionXML(xmlFilePath)) {
			this.error.setError("DS001", "The file is not an xml file");
			return false;
		}
		Document doc = SignatureUtils.documentFromFile(xmlFilePath, options.getXmlSchemaPath(), this.error);
		if (this.hasError()) {
			return false;
		}
		File f = new File(xmlFilePath);
		String baseURI = "";
		try {
			baseURI = f.toURI().toURL().toString();
		} catch (MalformedURLException e) {
			this.error.setError("DS002", "Error on baseURI");
			return false;
		}
		return verify(doc, baseURI, options.getIdentifierAttribute());

	}

	public boolean doVerifyWithCert(String xmlSigned, Certificate certificate, DSigOptions options) {
		this.error.cleanError();
		CertificateX509 cert = (CertificateX509) certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS003", "Certificate not loaded");
			return false;
		}
		Document doc = SignatureUtils.documentFromString(xmlSigned, options.getXmlSchemaPath(), this.error);
		if (this.hasError()) {
			return false;
		}
		String baseURI = "";
		return verify(doc, baseURI, cert, options.getIdentifierAttribute());
	}

	public boolean doVerifyFileWithCert(String xmlFilePath, Certificate certificate, DSigOptions options) {
		this.error.cleanError();
		if (!SignatureUtils.validateExtensionXML(xmlFilePath)) {
			this.error.setError("DS007", "The file is not an xml file");
			return false;
		}
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS005", "Certificate not loaded");
			return false;
		}
		Document doc = SignatureUtils.documentFromFile(xmlFilePath, options.getXmlSchemaPath(), this.error);
		if (this.hasError()) {
			return false;
		}
		File f = new File(xmlFilePath);
		String baseURI = "";
		try {
			baseURI = f.toURI().toURL().toString();
		} catch (MalformedURLException e) {
			this.error.setError("DS008", "Error on baseURI");
			return false;
		}

		return verify(doc, baseURI, cert, options.getIdentifierAttribute());
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private boolean doSignFileElementPKCS12(String xmlFilePath, String xPath, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, String dSigType, String canonicalizationType, String outputPath, String keyInfoType, String xmlSchemaPath, String id) {
		if (TransformsWrapper.getTransformsWrapper(dSigType, this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("DS013", "Not implemented DSigType");
			return false;
		}
		if (!SignatureUtils.validateExtensionXML(xmlFilePath)) {
			this.error.setError("DS014", "Not XML file");
			return false;
		}
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS015", "Certificate not loaded");
			return false;
		}
		Document xmlDoc = SignatureUtils.documentFromFile(xmlFilePath, xmlSchemaPath, this.error);
		if (this.hasError()) {
			return false;
		}

		String result = Sign(xmlDoc, (PrivateKeyManager)key, cert,dSigType, canonicalizationType,
				keyInfoType, xPath, id);
		if (result == null || SecurityUtils.compareStrings("", result)) {
			this.error.setError("DS016", "Error generating signature");
			return false;
		} else {
			String prefix = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
			return SignatureUtils.writeToFile(result, outputPath, prefix, this.error);
		}
	}

	private String doSignElementPKCS12(String xmlInput, String xPath, com.genexus.securityapicommons.commons.PrivateKey key,
			Certificate certificate, String dSigType, String canonicalizationType,
			String keyInfoType, String xmlSchemaPath, String id) {
		if (TransformsWrapper.getTransformsWrapper(dSigType, this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("DS017", "Not implemented DSigType");
			return "";
		}
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS018", "Certificate not loaded");
			return "";
		}
		Document xmlDoc = SignatureUtils.documentFromString(xmlInput, xmlSchemaPath, this.error);
		if (this.hasError()) {
			return "";
		}
		return Sign(xmlDoc, (PrivateKeyManager)key, cert, dSigType, canonicalizationType, keyInfoType,
				xPath, id);
	}

	private String doSignPKCS12(String xmlInput, com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate, String dSigType,
			String canonicalizationType, String keyInfoType, String xmlSchemaPath) {
		if (TransformsWrapper.getTransformsWrapper(dSigType, this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("DS019", "Not implemented DSigType");
			return "";
		}
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS020", "Certificate not loaded");
			return "";
		}
		Document xmlDoc = SignatureUtils.documentFromString(xmlInput, xmlSchemaPath, this.error);
		if (this.hasError()) {
			return "";
		}
		return Sign(xmlDoc, (PrivateKeyManager)key, cert, dSigType, canonicalizationType, keyInfoType,
				"", "");
	}

	private boolean doSignFilePKCS12(String xmlFilePath, com.genexus.securityapicommons.commons.PrivateKey key, Certificate certificate,
			String dSigType, String canonicalizationType, String outputPath,
			String keyInfoType, String xmlSchemaPath) {
		if (TransformsWrapper.getTransformsWrapper(dSigType, this.error) != TransformsWrapper.ENVELOPED) {
			error.setError("DS009", "Not implemented DSigType");
			return false;
		}
		if (!SignatureUtils.validateExtensionXML(xmlFilePath)) {
			this.error.setError("DS010", "Not XML file");
			return false;
		}
		CertificateX509 cert = (CertificateX509)certificate;
		if (!cert.Inicialized()) {
			this.error.setError("DS011", "Certificate not loaded");
		}
		Document xmlDoc = SignatureUtils.documentFromFile(xmlFilePath, xmlSchemaPath, this.error);
		if (this.hasError()) {
			return false;
		}
		String result = Sign(xmlDoc, (PrivateKeyManager)key, cert, dSigType, canonicalizationType,
				keyInfoType, "", "");
		if (result == null || SecurityUtils.compareStrings("", result)) {
			this.error.setError("DS012", "Error generating signature");
			return false;
		} else {
			String prefix = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
			return SignatureUtils.writeToFile(result, outputPath, prefix, this.error);
		}
	}

	private String Sign(Document xmlInput, PrivateKeyManager key, CertificateX509 certificate, String dSigType, String canonicalizationType, String keyInfoType, String xpath,
			String id) {
		SignatureElementType signatureElementType;
		if (!SecurityUtils.compareStrings(xpath, "")) {
			if (xpath.charAt(0) == '#') {
				signatureElementType = SignatureElementType.id;
				if (id == null || SecurityUtils.compareStrings(id, "")) {
					this.error.setError("DS021", "identifier attribute name missing");
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
		} catch (XMLSecurityException e) {
			this.error.setError("DS022", "Error on signature algorithm");
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
		} catch (TransformationException | XMLSignatureException e) {
			this.error.setError("DS024", "Transformation errors");
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
			} catch (XMLSecurityException e) {
				this.error.setError("DS025", "Error adding certificate to signature");
			}
			break;
		case KeyValue:
			sig.addKeyInfo(this.publicKey);
			break;
		case NONE:
			break;
		default:
			this.error.setError("DS026", "Undefined KeyInfo type");
			return "";
		}
		try {
			sig.sign(this.privateKey);
		} catch (XMLSignatureException e) {
			error.setError("DS027", "Error at signing");
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

	private boolean verify(Document doc, String baseURI, String id) {
		Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
				.item(0);
		if (id != null && !SecurityUtils.compareStrings(id, "")) {
			// Element ref = (Element) doc.getElementsByTagName(Constants._TAG_REFERENCE);
			Element ref = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_REFERENCE)
					.item(0);
			String sigId = ref.getAttribute(Constants._ATT_URI);
			if (sigId == null || SecurityUtils.compareStrings(sigId, "")) {
				this.error.setError("DS029", "Could not find Reference URI for id");
				return false;
			}
			Element idElement = (Element) SignatureUtils.getNodeFromID(doc, id, sigId, this.error);
			if (idElement == null) {
				this.error.setError("DS030", "Could not find node from ID");
				return false;
			}
			idElement.setIdAttribute(id, true);
		}

		try {
			XMLSignature signature = new XMLSignature(sigElement, baseURI);
			return signature.checkSignatureValue(signature.getKeyInfo().getPublicKey());
		} catch (XMLSecurityException e) {

			this.error.setError("DS031", "Error on signature verification");
			return false;
		}
	}

	private boolean verify(Document doc, String baseURI, CertificateX509 certificate, String id) {
		Element sigElement = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_SIGNATURE)
				.item(0);
		if (id != null && !SecurityUtils.compareStrings(id, "")) {
			Element ref = (Element) doc.getElementsByTagNameNS(Constants.SignatureSpecNS, Constants._TAG_REFERENCE)
					.item(0);
			String sigId = ref.getAttribute(Constants._ATT_URI);
			if (sigId == null || SecurityUtils.compareStrings(sigId, "")) {
				this.error.setError("DS032", "Could not find Reference URI for id");
				return false;
			}
			Element idElement = (Element) SignatureUtils.getNodeFromID(doc, id, sigId, this.error);
			if (idElement == null) {
				this.error.setError("DS033", "Could not find node from ID");
				return false;
			}
			idElement.setIdAttribute(id, true);
		}

		try {
			XMLSignature signature = new XMLSignature(sigElement, baseURI);
			PublicKey pk = certificate.getPublicKeyXML();
			return signature.checkSignatureValue(pk);
		} catch (XMLSecurityException e) {
			this.error.setError("DS034", "Error on verification");
			return false;
		}
	}
}
