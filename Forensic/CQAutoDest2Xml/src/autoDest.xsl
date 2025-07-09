<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="html" indent="yes"/>


  <xsl:template match="/">
  <html>
  <body>
   <xsl:for-each select="/autoFiles/autoFile">
  <h2><xsl:value-of select="@file"/></h2>
    <xsl:apply-templates select="document(@file)/AutomaticDestinations">
     <xsl:with-param name="appid" select="@appid"/>
    </xsl:apply-templates>
   </xsl:for-each>
  </body>
  <script>
<![CDATA[
function sortTable(n, appid) {
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.getElementById(appid);
  switching = true;
  //Set the sorting direction to ascending:
  dir = "asc"; 
  /*Make a loop that will continue until
  no switching has been done:*/
  while (switching) {
    //start by saying: no switching is done:
    switching = false;
    rows = table.rows;
    /*Loop through all table rows (except the
    first, which contains table headers):*/
    for (i = 1; i < (rows.length - 1); i++) {
      //start by saying there should be no switching:
      shouldSwitch = false;
      /*Get the two elements you want to compare,
      one from current row and one from the next:*/
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      /*check if the two rows should switch place,
      based on the direction, asc or desc:*/
      if (dir == "asc") {
        if(n == 0)
        {
          if (Number(x.innerHTML) > Number(y.innerHTML)) {
          shouldSwitch = true;
          break;
          }
        }
        else{
          if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
            //if so, mark as a switch and break the loop:
            shouldSwitch= true;
            break;
          }
        }
      } else if (dir == "desc") {
        if(n == 0)
        {
          if (Number(x.innerHTML) < Number(y.innerHTML)) {
          shouldSwitch = true;
          break;
          }
        }
        else{
          if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
            //if so, mark as a switch and break the loop:
            shouldSwitch = true;
            break;
          }
        }
      }
    }
    if (shouldSwitch) {
      /*If a switch has been marked, make the switch
      and mark that a switch has been done:*/
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      //Each time a switch is done, increase this count by 1:
      switchcount ++;      
    } else {
      /*If no switching has been done AND the direction is "asc",
      set the direction to "desc" and run the while loop again.*/
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}
]]>
</script>
  </html>
  </xsl:template>

<xsl:template match="/AutomaticDestinations">
<xsl:param name="appid"/>
  <h2>DestList</h2>
  <table border="1" id="_t{$appid}">
    <tr bgcolor="#9acd32">
      <th onclick="sortTable(0, '_t{$appid}')">Entry #</th>
      <th onclick="sortTable(1,'_t{$appid}')">Path</th>
      <th onclick="sortTable(2, '_t{$appid}')">Last Modified</th>
    </tr>
    <xsl:for-each select="DestList/DestListEntryV2">
    <tr>
      <td>
        <xsl:value-of select="@EntryNumber"/>
      </td>
      <td>
        <xsl:value-of select="@Path"/>
      </td>
      <td>
        <xsl:value-of select="@LastModified"/>
      </td>
    </tr>
    </xsl:for-each>
  </table>
  <br/>
  <h2>LNKs</h2>
  <table border="1">
    <tr bgcolor="#9acd32">
      <!-- <th>Entry #</th> -->
      <th>Entry #</th>
      <th>Path</th>
      <th>Name string</th>
      <th>Command line arguments</th>
      <!-- <th>Last Modified</th> -->
    </tr>
    <xsl:for-each select="LNKs/LNK">
    <tr>
      <!-- <td> -->
        <!-- <xsl:value-of select="@EntryNumber"/> -->
      <!-- </td> -->
      <td>
        <xsl:value-of select="position()"/>
      </td>
      <td>
        <xsl:value-of select="LinkInfo/@LocalBasePath"/>
      </td>
      <td>
        <xsl:value-of select="NAME_STRING/@String"/>
      </td>      <td>
        <xsl:value-of select="COMMAND_LINE_ARGUMENTS/@String"/>
      </td>
      <!-- <td> -->
        <!-- <xsl:value-of select="@LastModified"/> -->
      <!-- </td> -->
    </tr>
    </xsl:for-each>
  </table>

</xsl:template>

</xsl:stylesheet>