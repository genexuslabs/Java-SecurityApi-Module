package com.genexus.sftp;

import com.genexus.commons.sftp.SftpClientObject;
import com.genexus.securityapicommons.utils.SecurityUtils;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class SftpClient extends SftpClientObject {

	private ChannelSftp channel;
	private Session session;

	public SftpClient() {
		super();
		this.channel = null;
		this.session = null;
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - BEGIN ********/
	public boolean connect(SftpOptions options) {
		if(options.hasError())
		{
			this.error = options.getError();
			return false;
		}
		boolean useKey = false;
		if (SecurityUtils.compareStrings("", options.getKeyPath()) || SecurityUtils.compareStrings("", options.getUser()) || SecurityUtils.compareStrings("", options.getKeyPassword())) {
			useKey = false;
			if (SecurityUtils.compareStrings("", options.getUser())
					|| SecurityUtils.compareStrings("", options.getPassword())) {
				
				this.error.setError("SF001", "Authentication misconfiguration");
				return false;
			}else {
				useKey = false;
			}
		}else {
			useKey=true;
		}

		
		
		if (SecurityUtils.compareStrings("", options.getHost())) {
			this.error.setError("SF003", "Empty host");
			return false;
		}
		try {
			this.channel = setupJsch(options, useKey);
			this.channel.connect();
		} catch (JSchException e) {
			this.error.setError("SF004", e.getMessage() + e.getStackTrace());
			return false;
		}
		return true;
	}

	public boolean put(String localPath, String remoteDir) {
		if (this.channel == null) {
			this.error.setError("SF005", "The channel is invalid, reconect");
			return false;
		}
		try {
			this.channel.put(localPath, remoteDir);
		} catch (SftpException e) {
			this.error.setError("SF006", e.getMessage());
			return false;
		}
		return true;
	}

	public boolean get(String remoteFilePath, String localDir) {
		if (this.channel == null) {
			this.error.setError("SF007", "The channel is invalid, reconect");
			return false;
		}
		try {
			this.channel.get(remoteFilePath, localDir);
		} catch (SftpException e) {
			this.error.setError("SF008", e.getMessage());
			return false;
		}
		return true;
	}

	public void disconnect() {
		if (this.channel != null) {
			this.channel.disconnect();
		}
		if(this.session != null)
		{
			this.session.disconnect();
		}
	}
	
	public String getWorkingDirectory()
	{
		if (this.channel != null)
		{
			try {
				return this.channel.pwd();
			} catch (SftpException e) {
				this.error.setError("SF017", "Could not get working directory, try reconnect");
				return "";
			}
		}
		return "";
	}

	/******** EXTERNAL OBJECT PUBLIC METHODS - END ********/

	private ChannelSftp setupJsch(SftpOptions options, boolean useKey) throws JSchException {
		JSch jsch = new JSch();
		
		
		if (useKey) { 
			jsch.addIdentity(options.getKeyPath(), options.getKeyPassword());
			
			this.session = jsch.getSession(options.getUser(),options.getHost());
			if(options.getAllowHostKeyChecking()) {
				if(SecurityUtils.compareStrings("", options.getKnownHostsPath()))
				{
					this.error.setError("SF009", "Options misconfiguration, known_hosts path is empty but host key checking is true");
				}
				jsch.setKnownHosts(options.getKnownHostsPath());
			}else {
				this.session.setConfig("StrictHostKeyChecking", "no");
			}
			
		} else {
			this.session = jsch.getSession(options.getUser(), options.getHost(), options.getPort());
			this.session.setPassword(options.getPassword());
			this.session.setConfig("StrictHostKeyChecking", "no");
		}
		this.session.connect();
		return (ChannelSftp) this.session.openChannel("sftp");
	}
}
