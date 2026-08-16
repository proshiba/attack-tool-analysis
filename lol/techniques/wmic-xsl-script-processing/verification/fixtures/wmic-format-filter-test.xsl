<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:ms="urn:schemas-microsoft-com:xslt"
  xmlns:lab="urn:wmic-format-filter-test">
  <ms:script language="JScript" implements-prefix="lab"><![CDATA[
    function marker() {
      var shell = new ActiveXObject("WScript.Shell");
      var path = shell.ExpandEnvironmentStrings("%TEMP%\\wmic-format-filter-marker.txt");
      var file = new ActiveXObject("Scripting.FileSystemObject").CreateTextFile(path, true);
      file.WriteLine("benign-wmic-format-filter-test");
      file.Close();
      return "benign-wmic-format-filter-test";
    }
  ]]></ms:script>
  <xsl:output method="text"/>
  <xsl:template match="/">
    <xsl:value-of select="lab:marker()"/>
  </xsl:template>
</xsl:stylesheet>
