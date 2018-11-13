function AddServerNode(currentNumberOfServers)
{
    var nextNode = currentNumberOfServers + 1;
    var table = $("#tblServerNodes");
    var content = "<tr><td><input type='text' id='txtServerName" + nextNode + "' /></td><td><select id='ddlMinRole" + nextNode + "'>";
    content += "<option value='Application'>Application</option>";
    content += "<option value='ApplicationWithSearch'>Application with Search</option>";
    content += "<option value='Custom'>Custom</option>";
    content += "<option value='DistributedCache'>Distributed Cache</option>";
    content += "<option value='Search'>Search</option>";
    content += "<option value='SingleServerFarm'>Single Server Farm</option>";
    content += "<option value='WebFrontEndWithDistributedCache'>Web Front-End with Distributed Cache</option>";
    content += "<option value='WebFrontEnd'>Web Front-End</option>";
    content += "</select></td>";
    content += "<td><a href='#' class='spdsc-addnode' onclick='AddServerNode(" + nextNode + ")'>";
    content += "<img src='images/plusicon.png' alt='Add a Server to the Farm' /></a></td></tr>";
    table.append(content);
    $("#spdsc-addserver" + currentNumberOfServers).hide();
}