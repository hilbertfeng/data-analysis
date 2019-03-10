# author:Hilbert
from flask_wtf import Form
from flask_wtf.file import FileField
from app.get_filter import GetField
from wtforms.validators import DataRequired, AnyOf

# upload form
class Upload(Form):
    pcap = FileField('pcap', validators=[DataRequired()])

class ProtoFilter(Form):
    value = FileField('value')
    filter_type = FileField('filter_type', validators=[DataRequired(), AnyOf(u'all'
                                                                              u'proto',u'ipsrc',u'ipdst')])

class UserFilter(Form):
    user_name = GetField('user_name')
    mobile = GetField('mobile_no')
    staff_no = GetField('staff_no')

