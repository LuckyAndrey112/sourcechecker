from flask_wtf import FlaskForm
from wtforms import TextAreaField, SubmitField, IntegerField, SelectField, BooleanField, RadioField
from wtforms.validators import DataRequired, ValidationError, NumberRange


class CheckerInterface(FlaskForm):
    sources = TextAreaField(label='Имя источника или список источников для проверки:',
                            validators=[DataRequired()],
                            render_kw=dict(placeholder=('LinuxServer @ hotel0d[UNICREDIT]\n' * 10), rows='20',
                                           cols='500'))
    qradar_host = RadioField(label='Консоль поиска', choices=[('bz', 'Bi.Zone Console'),
                                                              ], default='bz')
    check_all = BooleanField(label='Показать все источники', default=False)

    run = SubmitField('Запустить проверку')

    def validate_sources(self, sources):
        exclude_chars = (r'*?!\'"^+%/=}{$%#&\`~\|\\/;:йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.sources.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита и '
                                      f'спецсимволы "[", "]", "@", "(", ")"')


class SourceTypes(FlaskForm):
    source_types = SelectField(label='Наименование источника', validators=[DataRequired()],
                               render_kw={'data-live-search': True})
    domain = SelectField(label='Информационная система', validators=[DataRequired()])
    check_time = IntegerField(label='Время поиска в минутах', default=30,
                              validators=[DataRequired(), NumberRange(min=10, max=1440)])
    run = SubmitField('Проверить')

    def validate_source_types(self, source_types):
        exclude_chars = (r'*?!\'"^+%/()=}{$%#&\`~\|\\/;:йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.source_types.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита и '
                                      f'числа')

    def validate_domain(self, domain):
        exclude_chars = (r'*?!\'"^+%/()=}{$%#&\`~\|\\/;:[]йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.domain.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита, пробел и "-"')


class SourceTypesMP(SourceTypes):
    def validate_domain(self, source_types):
        exclude_chars = (r'*?!\'"^+%/=}{$%#&\`~\\\/;:йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.source_types.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита и '
                                      f'числа'
                                      f'')
    def validate_source_types(self, source_types):
        exclude_chars = (r'*?!\'"^+%/()=}{$%#&\`~\\\/;:йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.source_types.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита и '
                                      f'числа')
class ClusterForm(FlaskForm):
    cluster_name = SelectField(label='Наименование кластера', validators=[DataRequired()])
    run = SubmitField('Проверить')


class MPCheckerInterface(FlaskForm):
    sources = TextAreaField(label='Имя источника или список источников для проверки:',
                            validators=[DataRequired()],
                            render_kw=dict(placeholder=('Microsoft|Windows @ dc01.sec.rambler.tech[RAMBLER]\n' * 10), rows='20',
                                           cols='500'))
    customer = SelectField(label='Заказчик', validators=[DataRequired()])
    check_all = BooleanField(label='Показать все источники', default=False)
    run = SubmitField('Запустить проверку')


    def validate_sources(self,source):
        exclude_chars = (r'*?!\'"^+%/=}{$%#&\`~\\\/;:йцукенгшщзхъёфывапролджэячсмитьбю'
                         r'ЙЦУКЕНГШЩЗХЪЁФЫВАПРОЛДЖЭЯЧСМИТЬБЮ')
        for char in self.sources.data:
            if char in exclude_chars:
                raise ValidationError(f'Поле может содержать только буквы английского алфавита и '
                                      f'спецсимволы "[", "]", "@", "(", ")"')
