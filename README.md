# S2-061 (CVE-2020-17530)
some struts tag ,  attributes which out of the range will call SetDynamicAttribute() function, it will cause ONGL expression execute


**filter by python**

default struts tag list,  these dynamic-attribute options are true.
when code review，check the lists:
```
a:'accesskey','action','anchor','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','encode','errorPosition','escapeAmp','forceAddSchemeHostAndPort','href','id','includeContext','includeParams','javascriptTooltip','key','label','labelSeparator','labelposition','method','name','namespace','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','openTemplate','portletMode','portletUrlType','requiredLabel','requiredPosition','scheme','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value','windowState'
checkbox:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','fieldValue','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
checkboxlist:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','list','listCssClass','listCssStyle','listKey','listLabelKey','listTitle','listValue','listValueKey','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
datetextfiled:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','format','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
file:'accept','accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','size','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
hidden:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
form:'acceptcharset','accesskey','action','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','enctype','errorPosition','focusElement','id','includeContext','javascriptTooltip','key','label','labelSeparator','labelposition','method','name','namespace','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onreset','onselect','onsubmit','openTemplate','portletMode','requiredLabel','requiredPosition','style','tabindex','target','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','validate','value','windowState'
head:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
label:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','for','id','javascriptTooltip','key','label','labelSeparator','labelposition','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredLabel','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
password:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','maxLength','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','readonly','requiredLabel','requiredPosition','showPassword','size','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','type','value'
radio:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','list','listCssClass','listCssStyle','listKey','listLabelKey','listTitle','listValue','listValueKey','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
reset:'accesskey','action','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','method','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','openTemplate','requiredLabel','requiredPosition','src','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','type','value'
select:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','emptyOption','errorPosition','headerKey','headerValue','id','javascriptTooltip','key','label','labelSeparator','labelposition','list','listCssClass','listCssStyle','listKey','listLabelKey','listTitle','listValue','listValueKey','multiple','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','requiredLabel','requiredPosition','size','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value'
submit:'accesskey','action','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','method','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','openTemplate','requiredLabel','requiredPosition','src','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','type','value'
textarea:'accesskey','action','anchor','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','encode','errorPosition','escapeAmp','forceAddSchemeHostAndPort','href','id','includeContext','includeParams','javascriptTooltip','key','label','labelSeparator','labelposition','method','name','namespace','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','openTemplate','portletMode','portletUrlType','requiredLabel','requiredPosition','scheme','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','value','windowState'
textfield:'accesskey','class','cssClass','cssErrorClass','cssErrorStyle','cssStyle','disabled','errorPosition','id','javascriptTooltip','key','label','labelSeparator','labelposition','maxLength','name','onblur','onchange','onclick','ondblclick','onfocus','onkeydown','onkeypress','onkeyup','onmousedown','onmousemove','onmouseout','onmouseover','onmouseup','onselect','readonly','requiredLabel','requiredPosition','size','style','tabindex','template','templateDir','theme','title','tooltip','tooltipConfig','tooltipCssClass','tooltipDelay','tooltipIconPath','type','value'

```


when pentest,you can detect fo html tag's attribute, attributes out of the range will be regard as exist s2-061

```
tag_a = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle',
         'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href', 'id',
         'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator', 'labelposition',
         'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown',
         'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect',
         'openTemplate', 'portletMode', 'portletUrlType', 'requiredLabel', 'requiredPosition', 'scheme', 'style',
         'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass',
         'tooltipDelay', 'tooltipIconPath', 'value', 'windowState'}

tag_form = {'acceptcharset', 'accesskey', 'action', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle',
            'disabled', 'enctype', 'errorPosition', 'focusElement', 'id', 'includeContext', 'javascriptTooltip', 'key',
            'label', 'labelSeparator', 'labelposition', 'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick',
            'ondblclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout',
            'onmouseover', 'onmouseup', 'onreset', 'onselect', 'onsubmit', 'openTemplate', 'portletMode',
            'requiredLabel', 'requiredPosition', 'style', 'tabindex', 'target', 'template', 'templateDir', 'theme',
            'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'validate',
            'value', 'windowState'}

tag_label = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
             'errorPosition', 'for', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator', 'labelposition',
             'name', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup',
             'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect', 'requiredLabel',
             'requiredLabel', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip',
             'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value'}

tag_select = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled', 'emptyOption',
              'errorPosition', 'headerKey', 'headerValue', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
              'labelposition', 'list', 'listCssClass', 'listCssStyle', 'listKey', 'listLabelKey', 'listTitle',
              'listValue', 'listValueKey', 'multiple', 'name', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus',
              'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover',
              'onmouseup', 'onselect', 'requiredLabel', 'requiredPosition', 'size', 'style', 'tabindex', 'template',
              'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay',
              'tooltipIconPath', 'value'}

tag_textarea = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle',
                'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href', 'id',
                'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
                'labelposition', 'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick', 'ondblclick',
                'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout',
                'onmouseover', 'onmouseup', 'onselect', 'openTemplate', 'portletMode', 'portletUrlType',
                'requiredLabel', 'requiredPosition', 'scheme', 'style', 'tabindex', 'template', 'templateDir', 'theme',
                'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value',
                'windowState'}

tag_input = {'accept', 'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
             'errorPosition', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator', 'labelposition', 'name',
             'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup',
             'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect', 'requiredLabel',
             'requiredPosition', 'size', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip',
             'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value', 'maxLength', 'readonly',
             'showPassword', 'type', 'action', 'method', 'openTemplate', 'src', 'fieldValue', 'list', 'listCssClass',
             'listCssStyle', 'listKey', 'listLabelKey', 'listTitle', 'listValue', 'listValueKey', 'format'}
```
