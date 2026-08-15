<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:lab="urn:wmic-lab">
  <ms:script language="VBScript" implements-prefix="lab"><![CDATA[
    Function marker()
      Dim shell
      Set shell = CreateObject("WScript.Shell")
      shell.Run "cmd.exe /c echo benign-http-vbscript>C:\lab\wmic-http-vbscript-marker.txt", 0, True
      marker = "benign-http-vbscript"
    End Function
  ]]></ms:script>
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="lab:marker()"/>
  </xsl:template>
</xsl:stylesheet>
