var openid = require('openid');

/* 
 * Attribute Exchange Extension
 * http://openid.net/specs/openid-attribute-exchange-1_0.html 
 * Also see:
 *  - http://www.axschema.org/types/ 
 *  - http://code.google.com/intl/en-US/apis/accounts/docs/OpenID.html#Parameters
 */
// TODO: count handling

var attributeMapping = {
    'http://axschema.org/namePerson/first': 'firstname',
    'http://axschema.org/namePerson/last': 'lastname',
    'http://axschema.org/namePerson/friendly': 'nickname',
    'http://axschema.org/namePerson': 'fullname',

    'http://axschema.org/company/name': 'ppige_organism_name',
    'http://axschema.org/contact/postalAddress/business': 'ppige_organism_id',
    'http://axschema.org/namePerson/friendly': 'ppige_uid',
    'http://axschema.org/media/biography': 'ppige_roles',
    'http://axschema.org/birthDate/birthday': 'ppige_contribute_geocatalog'
};

var AttributeExchange = module.exports = function AttributeExchange(options) 
{ 
  this.requestParams = {'openid.ns.ax': 'http://openid.net/srv/ax/1.0',
    'openid.ax.mode' : 'fetch_request'};
  var required = [];
  var optional = [];
  for (var ns in options)
  {
    if (!options.hasOwnProperty(ns)) { continue; }
    if (options[ns] == 'required')
    {
      required.push(ns);
    }
    else
    {
      optional.push(ns);
    }
  }
  var self = this;
  required = required.map(function(ns, i) 
  {
    var attr = attributeMapping[ns] || 'req' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  optional = optional.map(function(ns, i)
  {
    var attr = attributeMapping[ns] || 'opt' + i;
    self.requestParams['openid.ax.type.' + attr] = ns;
    return attr;
  });
  if (required.length)
  {
    this.requestParams['openid.ax.required'] = required.join(',');
  }
  if (optional.length)
  {
    this.requestParams['openid.ax.if_available'] = optional.join(',');
  }
}

AttributeExchange.prototype.fillResult = openid.AttributeExchange.prototype.fillResult;
