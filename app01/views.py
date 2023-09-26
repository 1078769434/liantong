from random import random

from PIL.Image import Image
from PIL.ImageDraw import ImageDraw
from PIL.ImageFont import ImageFont
from django.contrib.auth.hashers import make_password, check_password
from django.http import HttpResponseForbidden
from django.shortcuts import render,redirect,HttpResponse
from app01 import models
from django.utils.safestring import mark_safe
# Create your views here.
from django import forms
from django.contrib.auth import logout, authenticate
from app01.models import Admin
import io
from captcha.fields import CaptchaField
def depart_list(request):
    """部门列表"""

    queryset = models.Department.objects.all()

    return render(request,'depart_list.html',{'queryset':queryset})

def depart_add(request):

    """添加部门"""
    if request.method =="GET":
        return render(request,'depart_add.html')

    if request.method == 'POST':
        #获取用户POST提交过来的数据
        title = request.POST.get("title")

        #保存到数据库
        models.Department.objects.create(title=title)

        #重定向回部门列表
        return redirect("/depart/list/")

def depart_delete(request):
    """删除部门"""

    #获取ID
    nid = request.GET.get('nid')

    #删除
    models.Department.objects.filter(id=nid).delete()

    #重定向部门列表
    return redirect("/depart/list/")

def depart_edit(request,nid):
    """ 修改部门"""
    if request.method =="GET":
        row_object  = models.Department.objects.filter(id=nid).first()

        return render(request,'depart_edit.html',{'row_object':row_object})

    #获取用户提交的标题
    title = request.POST.get("title")

    #根据ID找到数据库中的数据并进行更新
    models.Department.objects.filter(id=nid).update(title=title)

    #重定向回部门列表
    return redirect("/depart/list/")

def user_list(request):
    """用户管理"""

    queryset = models.UserInfo.objects.all()
    return render(request,'user_list.html',{'queryset':queryset})


def user_add(request):
    """添加用户"""
    if request.method =="GET":
        content = {
            'gender_choice':models.UserInfo.gender_choices,
            'depart_list':models.Department.objects.all(),
        }
        return render(request,'user_add.html',content)

    #获取用户提交的数据
    user = request.POST.get('user')
    pwd = request.POST.get('pwd')
    age = request.POST.get('age')
    account = request.POST.get('ac')
    ctime = request.POST.get('ctime')
    gender = request.POST.get('gd')
    depart_id = request.POST.get('dp')

    #添加到数据库中
    models.UserInfo.objects.create(name=user,password=pwd,age=age,account=account,create_time=ctime,gender=gender,depart_id=depart_id)

    return redirect('/user/list/')

from django import forms

class UserModelForm(forms.ModelForm):
    class Meta:
        model = models.UserInfo
        fields = ["name","password","age",'account','create_time','gender','depart']

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)

        for name,field in self.fields.items():
            field.widget.attrs = {"class":"form-control","placeholder":field.label}
def user_model_form_add(request):
    """添加用户 （ModelForm版本）"""
    if request.method == "GET":
        form = UserModelForm()
        return render(request,'user_model_form_add.html',{"form":form})

    #用户POST提交数据，数据校验
    form = UserModelForm(data=request.POST)
    if form.is_valid():

        form.save()
        return redirect('/user/list/')

    return render(request,'user_model_form_add.html',{"form":form})


def user_edit(request):
    """编辑用户"""
    row_object = models.UserInfo.objects.filter(id=nid).first()
    if request.method =="GET":


        form = UserModelForm(instance=row_object)
        return render(request,"user_edit.html")

    form = UserModelForm(data=request.POST,instance=row_object)
    if form.is_valid():
        form.save()
        return redirect('/user/list/')

    return render(request,'user_edit.html',{"form":form})


def user_delete(request,nid):
    models.UserInfo.objects.filter(id=nid).delete()
    return redirect('/user/list/')

from app01.utils.pageination import Pagination
def pretty_list(request):
    """靓号列表"""
    import copy
    query_dict = copy.deepcopy(request.GET)
    query_dict.mutable = True

    query_dict.setlist('page',[11])
    query_dict.urlencode()




    data_dict = {}
    search_data = request.GET.get('q',"")
    if search_data:
        data_dict['mobile__contains'] = search_data


    queryset = models.PrettyNum.objects.filter(**data_dict).order_by("-level")

    page_object = Pagination(request,queryset)
    page_queryset = page_object.page_queryset
    page_string = page_object.html()

    context = {
         "queryset": page_object.page_queryset,#分完页的数据
         "search_data": search_data,
         "page_string":page_string
    }



    return render(request,"pretty_list.html",context)

from django.core.validators import RegexValidator

class PrettyModelForm(forms.ModelForm):
    mobile = forms.CharField(
        label="手机号",
        validators=[RegexValidator(r'^1[3-9]\d{9}$','手机号格式错误'),],

    )

    class Meta:
        model = models.PrettyNum
        fields = ["mobile","price","level","statues"]

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)

        for name,field in self.fields.items():
            field.widget.attrs = {"class":"form-control","placeholder":field.label}
def pretty_add(request):
    """添加靓号"""
    if request.method == "GET":

        form = PrettyModelForm()
        return render(request,'pretty_add.html',{"form":form})
    form = PrettyModelForm(data=request.POST)

    if form.is_valid():
        form.save()
        return redirect('/pretty/list/')
    return render(request,'pretty_add.html',{"form":form})

class PrettyEditModelForm(forms.ModelForm):
    mobile = forms.CharField(
        label="手机号",
        validators=[RegexValidator(r'^1[3-9]\d{9}$', '手机号格式错误'), ],

    )

    class Meta:
        model = models.PrettyNum
        fields = ["mobile","price","level","statues"]

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)

        for name,field in self.fields.items():
            field.widget.attrs = {"class":"form-control","placeholder":field.label}
    def clean_mobile(self):


        txt_mobile = self.cleaned_data["mobile"]
        models.PrettyNum.objects.exclude(id=self.instance.pk).filter(mobile=txt_mobile).exists()
        if exists:
            raise ValidationError("手机号已存在")

        return txt_mobile
def pretty_edit(request,nid):
    """编辑靓号"""

    row_object = models.PrettyNum.objects.filter(id=nid).first()
    if request.method == "GET":
        form = PrettyEditModelForm(instance=row_object)
        return render(request,"pretty_edit.html",{"form":form})

    form = PrettyModelForm(data=request.POST,instance=row_object)

    if form.is_valid():
        form.save()
        return redirect('/pretty/list/')

    return render(request,'pretty_edit.html',{"form":form})

def pretty_delete(request,nid):
    models.PrettyNum.objects.filter(id=nid).delete()
    return redirect('/pretty/list/')


class LoginForm(forms.Form):
    username = forms.CharField(
        label="用户名",
        widget=forms.TextInput(attrs={"class":"form-control"}),
        required=True
    )
    password = forms.CharField(
        label="密码",
        widget=forms.PasswordInput(attrs={"class":"form-control"},render_value=True),
        required=True

    )

    captcha = CaptchaField()

# def generate_captcha(self, size=(200, 100), font_size=50):
#     # 生成随机验证码字符串
#     code = ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(4))
#
#     # 创建一个空白图片
#     image = Image.new('RGB', size, 'white')
#     draw = ImageDraw.Draw(image)
#
#     # 加载字体
#     font = ImageFont.truetype("arial.ttf", font_size)
#
#     # 在图片上绘制验证码
#     draw.text((10, 30), code, fill='black', font=font)
#
#     # 创建一个BytesIO对象，用于保存图片数据
#     image_data = io.BytesIO()
#     image.save(image_data, 'PNG')
#
#     return image_data.getvalue(), code



def login(request):
    if request.method == 'GET':
        form = LoginForm()
        # # 生成验证码图片
        # image, code = generate_captcha()
        #
        # # 将验证码保存到session中，用于验证用户输入
        # request.session['captcha_code'] = code
        return render(request,'login.html',{'form':form})
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username=request.POST.get('username')
            password=request.POST.get('password')

            admin=Admin.objects.filter(username=username).first()
            if admin:
                if check_password(password,admin.password):
                    return redirect('/pretty/list/')
            else:
                form.add_error('username','用户名或密码错误')
                return render(request,'login.html',{'form':form})

    return render(request,'login.html',{'form':form})
# def login(request):
#     """用户登录"""
#     if request.method == "GET":
#         form = LoginForm()
#         return render(request,'login.html',{'form':form})
#
#     form = LoginForm(data=request.POST)
#     if form.is_valid():
#         """form.cleaned_data属性来获取有效的、经过清理后的表单数据。 form.cleaned_data返回一个包含字段名和对应值的字典，其中键是表单类中定义的字段，在键中都是经过验证和清理后的有效数据。"""
#         admin_object = models.Admin.objects.filter(**form.cleaned_data).first()
#         if not admin_object:
#             form.add_error("password","用户名或密码错误")
#             return render(request,'login.html',{'form':form})
#         request.session["info"] = {'id':admin_object.id,'name':admin_object.username}
#         return redirect("/pretty/list/")
#     return render(request,'login.html',{'form':form})

def logout_view(request):

    """用户注销"""
    logout(request)
    return redirect('/login/')

from django.contrib.auth.forms import UserCreationForm
class RegistrationForm(forms.ModelForm):
    username = forms.CharField(label='用户名')
    password = forms.CharField(label='密码', widget=forms.PasswordInput)
    confirm_password = forms.CharField(label='重复密码', widget=forms.PasswordInput)
    class Meta:
        model = Admin
        fields = ['username','password']

def register(request):
    """用户注册"""
    if request.method =='GET':
        form = RegistrationForm()
        return render(request, 'register.html', {'form': form})
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        # 检查用户名是否已存在
        if Admin.objects.filter(username=username).exists():
            form.add_error('username', '该用户名已经被注册')
            return render(request, 'register.html', {'form':form})

        if not all([username,password,confirm_password]):
            return HttpResponseForbidden("缺少必要参数")

        #检查密码是否一致
        if password != confirm_password:
            form.add_error('password','密码不一致')
            return render(request, 'register.html', {'form': form})
        if form.is_valid():
            # 处理注册逻辑，例如创建用户
            hashed_password = make_password(password)
            user = Admin(username=username,password=hashed_password)
            user.save()
            return redirect('http://127.0.0.1:8000/login/')


    return render(request,'register.html',{'form':form})

