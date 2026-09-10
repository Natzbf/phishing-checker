import streamlit as st
import requests
import base64

st.set_page_config(page_title='Phishing Checker', page_icon='🛡️', layout='centered')
st.title('🛡️ أداة فحص الروابط الخبيثة')
st.write('قم بوضع الرابط أدناه للتحقق من أمانه باستخدام قاعدة بيانات VirusTotal.')

api_key = st.text_input('أدخل مفتاح VirusTotal API الخاص بك:', type='password')
url_to_check = st.text_input('أدخل الرابط للفحص:')

def check_url(url, api):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    headers = {'accept': 'application/json', 'x-apikey': api}
    return requests.get(endpoint, headers=headers)

if st.button('فحص الرابط 🔍'):
    if not api_key or not url_to_check:
        st.warning('⚠️ يرجى إدخال مفتاح الـ API والرابط أولاً.')
    else:
        with st.spinner('جاري فحص الرابط...'):
            try:
                res = check_url(url_to_check, api_key)
                if res.status_code == 200:
                    stats = res.json()['data']['attributes']['last_analysis_stats']
                    mal, susp = stats.get('malicious', 0), stats.get('suspicious', 0)
                    st.markdown('---')
                    st.subheader('📊 نتيجة الفحص:')
                    if mal > 0 or susp > 0:
                        st.error('🚨 تحذير! الرابط قد يكون خبيثاً أو احتيالياً.')
                        st.write(f'- محركات اعتبرته خبيث: {mal}')
                        st.write(f'- محركات اعتبرته مشبوه: {susp}')
                    else:
                        st.success('✅ الرابط آمن! لم يتم اكتشاف أي تهديدات.')
                elif res.status_code == 404:
                    st.info('ℹ️ هذا الرابط جديد تماماً ولم يتم تحليله سابقاً.')
                else:
                    st.error(f'خطأ في الاتصال: {res.status_code}')
            except Exception as e:
                st.error(f'حدث خطأ: {e}')

