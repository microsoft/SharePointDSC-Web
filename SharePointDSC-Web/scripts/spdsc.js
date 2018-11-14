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
    content += "<td><a href='#' class='spdsc-addnode' onclick='AddServerNode(" + nextNode + "); return false;' id='spdsc-addserver" + nextNode + "'>";
    content += "<img src='images/plusicon.png' alt='Add a Server to the Farm' /></a></td></tr>";
    table.append(content);
    $("#spdsc-addserver" + currentNumberOfServers).html("<img src='images/checkmark.png' />");
}

function AddFarmAdmin(currentNumberofAdmins)
{
    var nextItem = currentNumberofAdmins + 1;
    var content = "<br />";
    content += "<input type='text' id='txtFarmAdmin" + nextItem + "' class='spdsc-widetextbox' />";
    content += "<a href='#' class='spdsc-addnode' onclick='AddFarmAdmin(" + nextItem + ");return false;'>";
    content += "<img src='images/plusicon.png' alt='Add a Farm Admin' id='spdsc-img-addfarmadmin" + nextItem + "' /></a>"
    $("#spdsc-img-addfarmadmin" + currentNumberofAdmins).hide();
    $("#spdsc-section-farmadmins").append(content);
}

function AddCustomSolution(currentNumberOfSolutions)
{
    var nextItem = currentNumberOfSolutions + 1;
    var content = "<tr>";
    content += "<td><input type='text' id='txtCustomSolutionPath" + nextItem + "' /></td>";
    content += "<td><input type='checkbox' id='chckCustomSolutionDeployed" + nextItem + "' /></td>";
    content += "<td><input type='text' id='txtCustomSolutionWebApps" + nextItem + "' /></td>";
    content += "<td><input type='text' id='txtCustomSolutionCompatibility" + nextItem + "' /></td>";
    content += "<td><a href='#' class='spdsc-addnode' onclick='AddCustomSolution(" + nextItem + ");return false;' id='spdsc-img-addcustomsolution" + nextItem + "'>";
    content += "<img src='images/plusicon.png' alt='Add a Custom Solution' /></a></td></tr>";
    $("#spdsc-table-customsolution").append(content);
    $("#spdsc-img-addcustomsolution" + currentNumberOfSolutions).html("<img src='images/checkmark.png' />");
}

function Toggle(sectionName, show)
{
    if(show)
    {
        $("#" + sectionName).show();
    }
    else
    {
        $("#" + sectionName).hide();
    }
}

function GenerateFiles()
{
    var reader = new FileReader();
    var loc = window.location.pathname;
    var dir = loc.substring(0, loc.lastIndexOf('/'));
    var rawFile = new XMLHttpRequest();
    try {
        rawFile.open("GET", "file://" + dir + "/powershell/SharePointDSC.ps1", false);
        rawFile.onreadystatechange = function () {
            if (rawFile.readyState === 4) {
                if (rawFile.status === 200 || rawFile.status === 0) {
                    var allText = rawFile.responseText;
                    alert(allText);
                }
            }
        };
    }
    catch(err){
        rawFile.open("GET", windows.location.href + "powershell/SharePointDSC.ps1", false);
        rawFile.onreadystatechange = function () {
            if (rawFile.readyState === 4) {
                if (rawFile.status === 200 || rawFile.status === 0) {
                    var allText = rawFile.responseText;
                    alert(allText);
                }
            }
        };
    }
    rawFile.send(null);
}