import streamlit as st
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dateutil import parser
from collections import defaultdict, Counter
import pytz
import plotly.graph_objects as go
import numpy as np
import concurrent.futures

def fetch_xml(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        st.error(f"Erreur lors de la récupération du XML: {str(e)}")
        return None

def is_sitemap_index(xml_content):
    soup = BeautifulSoup(xml_content, 'xml')
    return soup.find('sitemapindex') is not None

def parse_sitemap_index(xml_content):
    soup = BeautifulSoup(xml_content, 'xml')
    sitemaps = soup.find_all('sitemap')
    sitemap_data = []
    
    for sitemap in sitemaps:
        loc = sitemap.find('loc')
        last_mod = sitemap.find('lastmod')
        
        if loc:
            sitemap_info = {
                'url': loc.text,
                'lastmod': parser.parse(last_mod.text) if last_mod else None
            }
            sitemap_data.append(sitemap_info)
    
    return sitemap_data

def parse_sitemap(xml_content):
    if not xml_content:
        return None, None, None
    
    soup = BeautifulSoup(xml_content, 'xml')
    urls = soup.find_all('url')
    
    unique_urls = set()
    last_mod_dates = []
    tags_info = defaultdict(set)
    
    for url in urls:
        loc = url.find('loc')
        last_mod = url.find('lastmod')
        
        if loc:
            unique_urls.add(loc.text)
        
        if last_mod:
            try:
                last_mod_date = parser.parse(last_mod.text)
                if last_mod_date.tzinfo is None:
                    last_mod_date = pytz.UTC.localize(last_mod_date)
                last_mod_dates.append(last_mod_date)
            except:
                continue

        # Detect standard tags
        if url.find('changefreq'):
            tags_info['standard'].add('changefreq')
        if url.find('priority'):
            tags_info['standard'].add('priority')

        # Detect image tags
        image_tags = url.find_all(lambda tag: tag.name and 'image:' in tag.name)
        if image_tags:
            for tag in image_tags:
                tags_info['image'].add(tag.name.split('image:')[1])

        # Detect video tags
        video_tags = url.find_all(lambda tag: tag.name and 'video:' in tag.name)
        if video_tags:
            for tag in video_tags:
                tags_info['video'].add(tag.name.split('video:')[1])

        # Detect news tags
        news_tags = url.find_all(lambda tag: tag.name and 'news:' in tag.name)
        if news_tags:
            for tag in news_tags:
                tags_info['news'].add(tag.name.split('news:')[1])

        # Detect language alternatives
        xhtml_links = url.find_all('xhtml:link')
        if xhtml_links:
            tags_info['language'].add('alternate')

        # Detect mobile tags
        if url.find('mobile:mobile'):
            tags_info['mobile'].add('mobile')
    
    return unique_urls, last_mod_dates, dict(tags_info)

def fetch_and_parse_sitemap(sitemap_url):
    try:
        xml_content = fetch_xml(sitemap_url)
        if xml_content:
            urls, dates, tags_info = parse_sitemap(xml_content)
            return {
                'url': sitemap_url,
                'urls': urls,
                'dates': dates,
                'tags_info': tags_info,
                'success': True
            }
    except Exception as e:
        return {
            'url': sitemap_url,
            'success': False,
            'error': str(e)
        }

def analyze_dates(dates):
    if not dates:
        return {'24h': 0, 'week': 0, 'month': 0, 'year': 0}
        
    now = datetime.now(pytz.UTC)
    
    last_24h = now - timedelta(days=1)
    last_week = now - timedelta(days=7)
    last_month = now - timedelta(days=30)
    last_year = now - timedelta(days=365)
    
    stats = {
        '24h': 0,
        'week': 0,
        'month': 0,
        'year': 0
    }
    
    for date in dates:
        if date.tzinfo != pytz.UTC:
            date = date.astimezone(pytz.UTC)
            
        if date >= last_24h:
            stats['24h'] += 1
        if date >= last_week:
            stats['week'] += 1
        if date >= last_month:
            stats['month'] += 1
        if date >= last_year:
            stats['year'] += 1
    
    return stats

def create_hour_heatmap(dates):
    if not dates:
        return go.Figure()
        
    dates_utc = [d.astimezone(pytz.UTC) if d.tzinfo != pytz.UTC else d for d in dates]
    
    hours = [d.hour for d in dates_utc]
    days = [d.weekday() for d in dates_utc]
    
    heatmap_data = np.zeros((7, 24))
    
    for day, hour in zip(days, hours):
        heatmap_data[day][hour] += 1
    
    if len(dates) > 0:
        heatmap_data = heatmap_data / len(dates) * 100
    
    jours = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche']
    heures = [f'{h:02d}h' for h in range(24)]
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data,
        x=heures,
        y=jours,
        colorscale='Viridis',
        hoverongaps=False,
        hovertemplate='Jour: %{y}<br>Heure: %{x}<br>Pourcentage: %{z:.1f}%<extra></extra>'
    ))
    
    fig.update_layout(
        title='Distribution des modifications par jour et heure (UTC)',
        xaxis_title='Heure de la journée',
        yaxis_title='Jour de la semaine',
        height=400
    )
    
    return fig

def display_tags_info(tags_info):
    if not tags_info:
        st.info("Aucune balise spéciale détectée dans ce sitemap")
        return

    st.subheader("Balises détectées")
    
    if 'standard' in tags_info:
        st.write("**Balises standard:**")
        st.write(", ".join(sorted(tags_info['standard'])))
    
    if 'image' in tags_info:
        st.write("**Balises image:**")
        st.write(", ".join(sorted(tags_info['image'])))
    
    if 'video' in tags_info:
        st.write("**Balises vidéo:**")
        st.write(", ".join(sorted(tags_info['video'])))
    
    if 'news' in tags_info:
        st.write("**Balises news:**")
        st.write(", ".join(sorted(tags_info['news'])))
    
    if 'language' in tags_info:
        st.write("**Balises de langue:**")
        st.write(", ".join(sorted(tags_info['language'])))
    
    if 'mobile' in tags_info:
        st.write("**Balises mobile:**")
        st.write(", ".join(sorted(tags_info['mobile'])))

def display_sitemap_stats(urls, dates, tags_info=None, title="Statistiques"):
    st.header(title)
    
    if urls:
        st.metric('Nombre total d\'URLs', len(urls))
    
    if dates:
        stats = analyze_dates(dates)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric('Dernières 24h', stats['24h'])
        with col2:
            st.metric('Dernière semaine', stats['week'])
        with col3:
            st.metric('Dernier mois', stats['month'])
        with col4:
            st.metric('Dernière année', stats['year'])
        
        st.plotly_chart(create_hour_heatmap(dates), use_container_width=True)
    
    if tags_info:
        display_tags_info(tags_info)

# Interface Streamlit
st.title('Analyseur de Sitemap XML')

# Input URL
xml_url = st.text_input('Entrez l\'URL du sitemap XML')

if xml_url:
    with st.spinner('Analyse en cours...'):
        # Récupération du XML initial
        xml_content = fetch_xml(xml_url)
        
        if xml_content:
            # Vérifier si c'est un sitemap index
            if is_sitemap_index(xml_content):
                st.info('Sitemap Index détecté')
                
                # Parser le sitemap index
                sitemaps = parse_sitemap_index(xml_content)
                st.metric('Nombre de sitemaps', len(sitemaps))
                
                # Récupérer tous les sitemaps en parallèle
                all_urls = set()
                all_dates = []
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    future_to_url = {executor.submit(fetch_and_parse_sitemap, sitemap['url']): sitemap['url'] 
                                   for sitemap in sitemaps}
                    
                    results = []
                    for future in concurrent.futures.as_completed(future_to_url):
                        result = future.result()
                        results.append(result)
                        if result['success']:
                            if result['urls']:
                                all_urls.update(result['urls'])
                            if result['dates']:
                                all_dates.extend(result['dates'])
                
                # Afficher les stats globales
                display_sitemap_stats(all_urls, all_dates, "Statistiques Globales")
                
                # Afficher les stats individuelles
                st.header('Statistiques par Sitemap')
                for result in results:
                    title = f"Sitemap: {result['url']}"
                    if result['success']:
                        url_count = len(result['urls']) if result['urls'] else 0
                        title += f" ({url_count} URLs)"
                    else:
                        title += " (Failed)"
                    with st.expander(title):
                        if result['success']:
                            display_sitemap_stats(result['urls'], result['dates'], result['tags_info'])
                        else:
                            st.error(f"Erreur: {result['error']}")
                
            else:
                # Traitement d'un sitemap normal
                unique_urls, last_mod_dates, tags_info = parse_sitemap(xml_content)
                if unique_urls and last_mod_dates:
                    display_sitemap_stats(unique_urls, last_mod_dates, tags_info)
                    
                    if st.checkbox('Afficher toutes les URLs'):
                        st.write(list(unique_urls))
                else:
                    st.error('Aucune URL ou date de modification trouvée dans le sitemap') 