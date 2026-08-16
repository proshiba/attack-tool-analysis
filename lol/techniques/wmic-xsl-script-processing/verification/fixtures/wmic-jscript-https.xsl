<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:lab="urn:wmic-lab">
  <ms:script language="JScript" implements-prefix="lab"><![CDATA[
    function marker() {
      var shell = new ActiveXObject("WScript.Shell");
      shell.Run("cmd.exe /c echo benign-https-jscript>C:\\lab\\wmic-https-marker.txt", 0, true);
      return "benign-https-jscript";
    }
  ]]></ms:script>
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="lab:marker()"/>
  </xsl:template>
</xsl:stylesheet>
