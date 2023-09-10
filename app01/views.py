from django.shortcuts import render,redirect,HttpResponse
from app01 import models
from django.utils.safestring import mark_safe
# Create your views here.
from django import forms
from django.contrib.auth import logout
def depart_list(request):
    """部门列表"""

    queryset = models.Department.objects.all()

    return render(request,'depart_list.html',{'queryset':queryset})

def depart_add(request):

    """添加部门"""
    if request.method =="GET":
        return render(request,'depart_add.html')

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
def login(request):
    """用户登录"""
    if request.method == "GET":
        form = LoginForm()
        return render(request,'login.html',{'form':form})

    form = LoginForm(data=request.POST)
    if form.is_valid():
        admin_object = models.Admin.objects.filter(**form.cleaned_data).first()
        if not admin_object:
            form.add_error("password","用户名或密码错误")
            return render(request,'login.html',{'form':form})
        request.session["info"] = {'id':admin_object.id,'name':admin_object.username}
        return redirect("/pretty/list/")
    return render(request,'login.html',{'form':form})

def logout_view(request):

    """用户注销"""
    logout(request)
    return redirect('/login/')