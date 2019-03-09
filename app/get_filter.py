from flask_wtf.file import FileField

class GetField(FileField):
    def process_formdata(self, valuelist):
        valuelist = (x for x in valuelist)
        data = next(valuelist, None)
        if data is not None:
            self.data = data
        else:
            self.raw_data = ()
